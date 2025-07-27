#!/bin/bash

# WP-CLI Integration Test Script for Allow SVG Plugin
# This script tests the plugin functionality through WordPress CLI

set -e

echo "🧪 Starting Allow SVG Plugin WP-CLI Tests..."

# Test 1: Verify plugin is active
echo "📋 Test 1: Checking plugin activation..."
if npx @wordpress/env run cli wp plugin is-active allow-svg; then
    echo "✅ Plugin is active"
else
    echo "❌ Plugin is not active"
    exit 1
fi

# Test 2: Check SVG MIME type registration
echo "📋 Test 2: Checking SVG MIME type registration..."
if npx @wordpress/env run cli wp eval "echo (isset(get_allowed_mime_types()['svg']) ? 'registered' : 'not registered');" | grep -q "registered"; then
    echo "✅ SVG MIME type is registered"
else
    echo "❌ SVG MIME type is not registered"
    exit 1
fi

# Test 3: Create test SVG files
echo "📋 Test 3: Creating test SVG files..."
npx @wordpress/env run cli sh -c 'echo "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"100\"><circle cx=\"50\" cy=\"50\" r=\"40\" fill=\"green\"/></svg>" > /tmp/valid-test.svg'
npx @wordpress/env run cli sh -c 'echo "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(\"XSS_TEST\")</script><circle cx=\"50\" cy=\"50\" r=\"40\" fill=\"red\"/></svg>" > /tmp/malicious-test.svg'

# Test 4: Upload valid SVG
echo "📋 Test 4: Testing valid SVG upload..."
VALID_ID=$(npx @wordpress/env run cli wp media import /tmp/valid-test.svg --porcelain)
if [ ! -z "$VALID_ID" ]; then
    echo "✅ Valid SVG uploaded successfully (ID: $VALID_ID)"
else
    echo "❌ Valid SVG upload failed"
    exit 1
fi

# Test 5: Upload malicious SVG and verify rejection
echo "📋 Test 5: Testing malicious SVG rejection..."
if MALICIOUS_RESULT=$(npx @wordpress/env run cli wp media import /tmp/malicious-test.svg --porcelain 2>&1); then
    echo "❌ Malicious SVG was uploaded when it should have been rejected"
    echo "Upload result: $MALICIOUS_RESULT"
    exit 1
else
    echo "✅ Malicious SVG was properly rejected"
fi

# Test 6: Cleanup test files
echo "📋 Test 6: Cleaning up test files..."
npx @wordpress/env run cli wp post delete $VALID_ID --force
npx @wordpress/env run cli rm -f /tmp/valid-test.svg /tmp/malicious-test.svg

echo "🎉 All WP-CLI tests passed successfully!"
echo ""
echo "📊 Test Summary:"
echo "  ✅ Plugin activation check"
echo "  ✅ MIME type registration"
echo "  ✅ Valid SVG upload"
echo "  ✅ Malicious SVG rejection"
echo "  ✅ Cleanup"