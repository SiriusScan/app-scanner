#!/bin/bash
# Migration script to fix scan types in existing custom templates
# Converts: service-detection → discovery, vuln-scan → vulnerability

set -e

echo "🔧 Migrating Custom Template Scan Types"
echo "========================================"
echo ""

# Check if valkey is accessible
if ! docker exec sirius-valkey valkey-cli PING > /dev/null 2>&1; then
    echo "❌ Error: Cannot connect to ValKey"
    exit 1
fi

# Get all custom templates
echo "📋 Finding custom templates..."
TEMPLATES=$(docker exec sirius-valkey valkey-cli KEYS "scan:template:custom-*")

if [ -z "$TEMPLATES" ]; then
    echo "✅ No custom templates found - nothing to migrate"
    exit 0
fi

COUNT=0
MIGRATED=0

for TEMPLATE_KEY in $TEMPLATES; do
    COUNT=$((COUNT + 1))
    echo ""
    echo "📝 Processing: $TEMPLATE_KEY"
    
    # Get template JSON
    TEMPLATE_JSON=$(docker exec sirius-valkey valkey-cli GET "$TEMPLATE_KEY")
    
    # Check if it has old scan types
    if echo "$TEMPLATE_JSON" | grep -q "service-detection\|vuln-scan"; then
        echo "   Found old scan types - migrating..."
        
        # Replace scan types
        MIGRATED_JSON=$(echo "$TEMPLATE_JSON" | sed 's/"service-detection"/"discovery"/g' | sed 's/"vuln-scan"/"vulnerability"/g')
        
        # Update ValKey
        docker exec -i sirius-valkey valkey-cli SET "$TEMPLATE_KEY" "$MIGRATED_JSON" > /dev/null
        
        echo "   ✅ Migrated scan types:"
        echo "      service-detection → discovery"
        echo "      vuln-scan → vulnerability"
        
        MIGRATED=$((MIGRATED + 1))
    else
        echo "   ✅ Already using correct scan types - skipping"
    fi
done

echo ""
echo "========================================"
echo "📊 Migration Summary:"
echo "   Total templates: $COUNT"
echo "   Migrated: $MIGRATED"
echo "   Skipped: $((COUNT - MIGRATED))"
echo ""

if [ $MIGRATED -gt 0 ]; then
    echo "✅ Migration complete! Templates updated."
    echo ""
    echo "🔄 Please refresh your UI to see the changes."
else
    echo "✅ All templates already up to date!"
fi

echo ""

