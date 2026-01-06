#!/bin/bash
# Doxyfile generation and documentation building script
# 
# This script generates Doxygen documentation for the VisualNet Scanner project.
# Usage: ./build_docs.sh
#
# Prerequisites:
#   - doxygen (install via: brew install doxygen or apt-get install doxygen)
#   - graphviz (optional, for better diagrams: brew install graphviz)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOXYFILE="${PROJECT_ROOT}/Doxyfile"
OUTPUT_DIR="${PROJECT_ROOT}/docs/doxygen"

echo "=========================================="
echo "VisualNet Scanner Documentation Generator"
echo "=========================================="
echo ""

# Check if Doxyfile exists
if [ ! -f "$DOXYFILE" ]; then
    echo "❌ Error: Doxyfile not found at $DOXYFILE"
    exit 1
fi

echo "✓ Doxyfile found: $DOXYFILE"
echo "✓ Output directory: $OUTPUT_DIR"
echo ""

# Check if doxygen is installed
if ! command -v doxygen &> /dev/null; then
    echo "❌ Error: doxygen is not installed"
    echo ""
    echo "To install doxygen:"
    echo "  macOS: brew install doxygen"
    echo "  Ubuntu/Debian: apt-get install doxygen"
    echo "  Fedora: dnf install doxygen"
    exit 1
fi

DOXYGEN_VERSION=$(doxygen --version)
echo "✓ Found doxygen: $DOXYGEN_VERSION"
echo ""

# Check if graphviz is installed (optional)
if command -v dot &> /dev/null; then
    GRAPHVIZ_VERSION=$(dot -V 2>&1 | head -n1)
    echo "✓ Found graphviz: $GRAPHVIZ_VERSION"
    echo "  (Better diagrams will be generated)"
else
    echo "⚠ Warning: graphviz not found (optional)"
    echo "  Install for better diagrams: brew install graphviz"
fi
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo "📁 Creating output directory: $OUTPUT_DIR"
echo ""

# Run doxygen
echo "🔨 Generating documentation..."
echo "   This may take a minute..."
echo ""

cd "$PROJECT_ROOT"
doxygen "$DOXYFILE"

echo ""
echo "✅ Documentation generation complete!"
echo ""
echo "📖 Generated Files:"
echo "   - HTML: $OUTPUT_DIR/html/index.html"
echo ""
echo "🌐 To view documentation in browser:"
echo "   open file://$OUTPUT_DIR/html/index.html"
echo ""
echo "📚 Documentation Structure:"
echo "   - Files: Python modules (.py files)"
echo "   - Classes: Python classes with detailed Doxygen comments"
echo "   - Functions: All documented functions with @param, @return, @details"
echo "   - Source: Full source code browser with cross-references"
echo ""
