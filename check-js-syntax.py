#!/usr/bin/env python3
import re
import json

def extract_and_check_js():
    with open('templates/index.html', 'r') as f:
        content = f.read()
    
    # Find the main script block
    script_match = re.search(r'<script>(.*?)</script>', content, re.DOTALL)
    
    if not script_match:
        print("No script tag found!")
        return
    
    js_content = script_match.group(1)
    
    # Look for common JavaScript syntax errors
    lines = js_content.split('\n')
    
    errors_found = []
    
    for i, line in enumerate(lines, 1):
        # Check for template syntax that might break JS
        if '{{' in line and '}}' in line:
            # Check if it's in a string
            if not ('"' in line or "'" in line):
                errors_found.append(f"Line {i}: Template variable outside string: {line.strip()[:80]}")
        
        # Check for unescaped HTML entities in strings
        if '&lt;' in line and ('`' in line or '"' in line or "'" in line):
            # This is OK in template literals but might cause issues
            pass
        
        # Check for console.log statements (for debugging)
        if 'console.log' in line:
            print(f"Debug line {i}: {line.strip()[:80]}")
        
        # Check for alert statements
        if 'alert(' in line:
            print(f"Alert line {i}: {line.strip()[:80]}")
    
    # Check for unmatched quotes
    single_quotes = js_content.count("'")
    double_quotes = js_content.count('"')
    backticks = js_content.count('`')
    
    if single_quotes % 2 != 0:
        errors_found.append("Unmatched single quotes")
    if double_quotes % 2 != 0:
        errors_found.append("Unmatched double quotes")
    if backticks % 2 != 0:
        errors_found.append("Unmatched backticks")
    
    # Check for async/await issues
    async_functions = re.findall(r'async\s+function\s+(\w+)', js_content)
    print(f"Found {len(async_functions)} async functions")
    
    # Check if functions are properly closed
    function_opens = js_content.count('function')
    
    print(f"\nSummary:")
    print(f"- Total lines: {len(lines)}")
    print(f"- Functions found: {function_opens}")
    print(f"- Async functions: {async_functions[:5]}...")  # First 5
    
    if errors_found:
        print("\nPotential errors found:")
        for error in errors_found:
            print(f"  - {error}")
    else:
        print("\nNo obvious syntax errors found")
    
    # Look for the specific functions we need
    critical_functions = ['loadPendingRequests', 'bulkApproveSelected', 'bulkRejectSelected', 'approveRequest', 'rejectRequest']
    for func in critical_functions:
        if func in js_content:
            print(f"✓ Function '{func}' found")
            # Check if it's properly exposed to window
            if f'window.{func}' in js_content:
                print(f"  → Exposed to window object")
        else:
            print(f"✗ Function '{func}' NOT found")

if __name__ == '__main__':
    extract_and_check_js()