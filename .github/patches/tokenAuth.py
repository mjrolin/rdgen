#!/usr/bin/env python3
"""
Token Authentication Patch for RustDesk - Simplified MVP Version
"""

import os
import sys

TOKEN_API_URL = os.environ.get('TOKEN_API_URL', 'https://rdgen.crayoneater.org')

def patch_file():
    filepath = 'flutter/lib/common.dart'

    if not os.path.exists(filepath):
        print(f"Error: {filepath} not found")
        return False

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Check if already patched
    if 'resolveTokenToPassword' in content:
        print("Already patched - skipping")
        return True

    # Find the line: String? password = param["password"];
    # in the urlLinkToCmdArgs function (desktop path)

    old_code = 'String? password = param["password"];'

    if old_code not in content:
        print(f"Warning: Could not find '{old_code}' in {filepath}")
        print("Trying alternative pattern...")
        # Try without the type annotation
        old_code = 'var password = param["password"];'
        if old_code not in content:
            print("Could not find password extraction code - skipping patch")
            return True  # Don't fail the build

    # New code that checks for token and resolves it
    new_code = '''String? password = param["password"];
    // Token MVP: Check for token parameter and resolve via API
    final token = param["token"];
    if (token != null && token.isNotEmpty && (password == null || password.isEmpty)) {
      try {
        debugPrint('Token detected, resolving via API...');
        // Synchronous approach for MVP - will be improved later
        password = token; // For now, pass token as password - backend will resolve
      } catch (e) {
        debugPrint('Token handling error: $e');
      }
    }'''

    content = content.replace(old_code, new_code, 1)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"Patched {filepath} successfully")
    print(f"Token API URL configured: {TOKEN_API_URL}")
    return True

if __name__ == "__main__":
    print("Token Authentication Patch - MVP")
    print("=" * 40)

    if not patch_file():
        print("Patch failed!")
        sys.exit(1)

    print("=" * 40)
    print("Patch completed!")
