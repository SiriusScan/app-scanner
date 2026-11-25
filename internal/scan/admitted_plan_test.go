package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/store"
)

type revisionTemplateStore struct {
	store.KVStore
	reads     atomic.Int32
	revisions [2]string
}

func (s *revisionTemplateStore) GetValue(ctx context.Context, key string) (store.ValkeyResponse, error) {
	if key != TemplateKeyPrefix+"profile" {
		return s.KVStore.GetValue(ctx, key)
	}
	index := s.reads.Add(1) - 1
	if index >= int32(len(s.revisions)) {
		return store.ValkeyResponse{}, errors.New("unexpected template reread")
	}
	var response store.ValkeyResponse
	response.Message.Value = s.revisions[index]
	return response, nil
}

type planEventRecorder struct {
	*memoryScanLogger
	scanID string
	fields map[string]interface{}
}

func (r *planEventRecorder) LogScanEvent(id, event, message string, fields map[string]interface{}) {
	r.memoryScanLogger.LogScanEvent(id, event, message, fields)
	if event == "scan_plan_admitted" {
		r.scanID, r.fields = id, fields
	}
}

func TestAdmittedPlanUsesOneRevisionAcrossHostWorkers(t *testing.T) {
	sm, kv, logger := testManager(t, activeTestScan("run-a", 0))
	recorder := &planEventRecorder{memoryScanLogger: logger}
	sm.logger = recorder
	templates := &revisionTemplateStore{KVStore: kv, revisions: [2]string{
		`{"id":"profile","enabled_scripts":["fixture-a"],"scan_options":{"port_range":"80","scan_types":["vulnerability"],"exclude_ports":["22"],"max_retries":3}}`,
		`{"id":"profile","enabled_scripts":["fixture-b"],"scan_options":{"port_range":"443","scan_types":["vulnerability"],"max_retries":4}}`,
	}}
	sm.templateManager = NewTemplateManager(templates)

	const hosts = 8
	targets := make([]Target, 0, hosts)
	for i := 1; i <= hosts; i++ {
		targets = append(targets, Target{Value: fmt.Sprintf("192.0.2.%d", i), Type: SingleIP})
	}
	msg := ScanMessage{ID: "run-a", Options: ScanOptions{TemplateID: "profile", MaxRetries: 5}, Targets: targets, Priority: 1}
	submit := func(msg ScanMessage) {
		t.Helper()
		payload, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		sm.handleMessage(string(payload))
	}
	submit(msg)
	if got := len(sm.workerPool.tasks); got != hosts {
		t.Fatalf("queued %d hosts, want %d", got, hosts)
	}

	var workers sync.WaitGroup
	firstTask := <-sm.workerPool.tasks
	run := firstTask.run
	checkHost := func(task ScanTask, port string) {
		defer workers.Done()
		if task.run != run {
			t.Error("task lost its admitted run")
			return
		}
		host := task.run.forHostPorts(port)
		host.currentScanOptions.ExcludePorts[0] = "23"
		if _, err := host.vulnerabilityStrategy().(*NmapStrategy).executeWithContext(host.ctx, task.IP, func(config nmap.ScanConfig) (sirius.Host, error) {
			if config.PortRange != port || !slices.Equal(config.ScriptList, []string{"fixture-a"}) {
				t.Errorf("wrong host configuration: ports=%q scripts=%v", config.PortRange, config.ScriptList)
			}
			config.ScriptList[0] = "changed in adapter"
			return sirius.Host{}, nil
		}); err != nil {
			t.Errorf("fake adapter failed: %v", err)
		}
	}
	workers.Add(hosts)
	go checkHost(firstTask, "8000")
	for i := 1; i < hosts; i++ {
		go checkHost(<-sm.workerPool.tasks, fmt.Sprint(8000+i))
	}
	workers.Wait()
	if templates.reads.Load() != 1 {
		t.Fatalf("first run read template %d times", templates.reads.Load())
	}
	if run.currentScanOptions.PortRange != "80" || run.currentScanOptions.MaxRetries != 5 ||
		!slices.Equal(run.currentScanOptions.ExcludePorts, []string{"22"}) || !slices.Equal(run.scriptSelection, []string{"fixture-a"}) {
		t.Fatal("host or adapter changed the admitted plan")
	}
	if recorder.scanID != msg.ID || len(recorder.fields) != 2 || recorder.fields["template_id"] != "profile" ||
		recorder.fields["plan_digest"] != run.digest || run.digest == "" {
		t.Fatalf("unexpected plan provenance: %s %v", recorder.scanID, recorder.fields)
	}

	msg.ID, msg.Targets = "run-b", targets[:1]
	if err := kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, activeTestScan(msg.ID, 0))); err != nil {
		t.Fatal(err)
	}
	submit(msg)
	if len(sm.workerPool.tasks) != 1 {
		t.Fatal("second run did not schedule its target")
	}
	nextRun := (<-sm.workerPool.tasks).run
	if templates.reads.Load() != 2 || nextRun.digest == run.digest || nextRun.currentScanOptions.PortRange != "443" ||
		!slices.Equal(nextRun.vulnerabilityStrategy().(*NmapStrategy).ScriptList, []string{"fixture-b"}) {
		t.Fatal("subsequent run did not admit the new template revision")
	}
}

func TestTemplateAdmissionFailureQueuesNoWork(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		{name: "lookup error", want: "failed"},
		{name: "missing explicit selection", want: "failed"},
		{name: "cancelled lookup", want: "cancelled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm, kv, _ := testManager(t, activeTestScan("other-run", 1))
			const id = "admission-test"
			if err := kv.SetValue(sm.ctx, "scan:"+id, encodeTestScan(t, activeTestScan(id, 0))); err != nil {
				t.Fatal(err)
			}
			run, err := sm.newKeyedRun(id)
			if err != nil {
				t.Fatal(err)
			}
			msg := ScanMessage{ID: id, Options: ScanOptions{TemplateID: "profile"}, Targets: []Target{{Value: "192.0.2.1", Type: SingleIP}}}
			calls := 0
			run.handleScanMessage(msg, func(ctx context.Context, id string) (*Template, error) {
				calls++
				if tc.name == "lookup error" {
					return nil, errors.New("template unavailable")
				}
				template := &Template{ID: id, ScanOptions: TemplateOptions{ScanTypes: []string{"vulnerability"}}}
				if tc.name == "cancelled lookup" {
					template.EnabledScripts = []string{"fixture"}
					run.cancel()
					// A resolver that returns successfully after cancellation
					// must still be prevented from admitting the plan.
					return template, nil
				}
				return template, nil
			})
			if err := run.scanUpdater.UpdateForScan(sm.ctx, id, func(scan *store.ScanResult) error {
				if scan.Status != tc.want {
					t.Errorf("status = %q, want %q", scan.Status, tc.want)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || len(sm.workerPool.tasks) != 0 || len(sm.keyedRuns) != 0 || readTestScan(t, kv).Status != "running" {
				t.Fatal("failed admission scheduled work or changed another run")
			}
		})
	}
}

func TestAdmittedPlanKeepsOmittedAndAgentOnlyTemplatesDistinct(t *testing.T) {
	sm, kv, _ := testManager(t, store.ScanResult{ID: "agent-run", Status: "running", SubScans: map[string]store.SubScan{
		"agent": {Enabled: true, Status: "running"},
	}})
	run, err := sm.newScanRun("agent-run")
	if err != nil {
		t.Fatal(err)
	}
	msg := ScanMessage{ID: "agent-run", Options: ScanOptions{TemplateID: "agent-only"}, Targets: []Target{{Value: "192.0.2.1", Type: SingleIP}}}
	run.handleScanMessage(msg, func(_ context.Context, id string) (*Template, error) {
		return &Template{ID: id, ScanOptions: TemplateOptions{AgentScan: &AgentScanConfig{Enabled: true}}}, nil
	})
	state := readTestScan(t, kv)
	if !run.agentOnly || len(sm.workerPool.tasks) != 0 || len(state.SubScans) != 1 || state.SubScans["agent"].Status != "running" {
		t.Fatal("agent-only template changed network or agent execution")
	}

	omitted, err := resolveScanPlan(sm.ctx, ScanOptions{ScanTypes: []string{"vulnerability"}}, nil)
	if err != nil || omitted.agentOnly || len(omitted.scriptSelection) != 0 || omitted.digest == run.digest {
		t.Fatalf("omitted template lost its legacy selection behavior: %v", err)
	}
	_, err = resolveScanPlan(sm.ctx, ScanOptions{TemplateID: "profile"}, func(context.Context, string) (*Template, error) {
		return &Template{ID: "wrong-id"}, nil
	})
	var admissionError *templateAdmissionError
	if !errors.As(err, &admissionError) {
		t.Fatalf("mismatched named template returned %v", err)
	}
}

func TestAdmittedPlanCopiesInputsAndHasDeterministicDigest(t *testing.T) {
	template := Template{
		ID:             "profile",
		EnabledScripts: []string{"fixture"},
		ScanOptions:    TemplateOptions{ScanTypes: []string{"vulnerability"}, ExcludePorts: []string{"22"}},
	}
	options := ScanOptions{TemplateID: "profile", FingerprintProbes: []string{"probe"}}
	lookup := func(context.Context, string) (*Template, error) { return &template, nil }
	original, err := resolveScanPlan(context.Background(), options, lookup)
	if err != nil {
		t.Fatal(err)
	}
	template.Name, template.Description = "renamed", "edited description"
	repeated, err := resolveScanPlan(context.Background(), options, lookup)
	if err != nil || original.digest != repeated.digest || original.digest == "" {
		t.Fatalf("identical effective configuration produced a different digest: %v", err)
	}
	template.EnabledScripts[0] = "changed"
	template.ScanOptions.ScanTypes[0] = "changed"
	template.ScanOptions.ExcludePorts[0] = "changed"
	options.FingerprintProbes[0] = "changed"
	if original.scriptSelection[0] != "fixture" || original.currentScanOptions.ScanTypes[0] != "vulnerability" ||
		original.currentScanOptions.ExcludePorts[0] != "22" || original.currentScanOptions.FingerprintProbes[0] != "probe" {
		t.Fatal("admitted plan aliases request or template memory")
	}
}
