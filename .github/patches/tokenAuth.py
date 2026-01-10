#!/usr/bin/env python3
"""
Token Authentication Patch for RustDesk
Adds support for ?token= parameter in rustdesk:// URLs

When RustDesk receives a URL like:
  rustdesk://connection/new/123456?token=abc123

It will call the token API to resolve the token to a password:
  GET https://your-api.com/api/token/resolve/abc123
  Response: { "success": true, "password": "real_password" }

Then connect using the resolved password.
"""

import os
import sys
import re

# Token API URL - will be replaced by workflow with actual URL
TOKEN_API_URL = os.environ.get('TOKEN_API_URL', 'https://rdgen.example.com')

def patch_common_dart(filepath='flutter/lib/common.dart'):
    """Patch flutter/lib/common.dart to add token support"""

    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return False

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Check if already patched
    if 'resolveTokenToPassword' in content:
        print("Already patched - skipping")
        return True

    # 1. Add http import at the top (after other dart imports)
    import_line = "import 'package:http/http.dart' as http;\n"

    # Find a good place to add the import (after existing imports)
    import_pattern = r"(import 'package:flutter[^;]+;)"
    match = re.search(import_pattern, content)
    if match:
        insert_pos = match.end()
        content = content[:insert_pos] + '\n' + import_line + content[insert_pos:]
        print("Added http import")
    else:
        # Fallback: add at the very beginning after first import
        first_import = content.find("import '")
        if first_import != -1:
            end_of_first_import = content.find(';', first_import) + 1
            content = content[:end_of_first_import] + '\n' + import_line + content[end_of_first_import:]
            print("Added http import (fallback position)")

    # 2. Add the token resolution function before urlLinkToCmdArgs
    token_function = '''
// Token resolution for secure password transmission
// Added by RDGen token patch
Future<String?> resolveTokenToPassword(String token) async {
  const tokenApiUrl = '%s';
  try {
    final url = Uri.parse('$tokenApiUrl/api/token/resolve/$token');
    debugPrint('Resolving token: ${token.substring(0, 8)}...');

    final response = await http.get(url).timeout(
      const Duration(seconds: 10),
      onTimeout: () {
        debugPrint('Token resolution timeout');
        throw Exception('Timeout');
      },
    );

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      if (data['success'] == true && data['password'] != null) {
        debugPrint('Token resolved successfully');
        return data['password'] as String;
      }
    } else if (response.statusCode == 410) {
      debugPrint('Token expired or already used');
    } else if (response.statusCode == 404) {
      debugPrint('Token not found');
    }
  } catch (e) {
    debugPrint('Token resolution error: $e');
  }
  return null;
}

''' % TOKEN_API_URL

    # Find urlLinkToCmdArgs function and insert before it
    url_link_pattern = r'(List<String>\? urlLinkToCmdArgs\(Uri uri\))'
    match = re.search(url_link_pattern, content)
    if match:
        insert_pos = match.start()
        content = content[:insert_pos] + token_function + content[insert_pos:]
        print("Added resolveTokenToPassword function")
    else:
        print("Warning: Could not find urlLinkToCmdArgs function")
        return False

    # 3. Modify the password extraction to check for token
    # Find: String? password = param["password"];
    # And add token handling after it

    # Pattern for desktop path (args building)
    desktop_password_pattern = r'(String\? password = param\["password"\];)'

    token_check_code = '''String? password = param["password"];
    String? token = param["token"];

    // If token present and no password, resolve token (MVP - blocking call)
    if (token != null && token.isNotEmpty && (password == null || password.isEmpty)) {
      // For MVP: we'll pass token as password and handle in connect()
      // The actual resolution happens in the modified connect function
      password = 'TOKEN:$token';
    }'''

    # Replace the password extraction
    content = re.sub(desktop_password_pattern, token_check_code, content, count=1)
    print("Modified password extraction for desktop")

    # 4. Also handle mobile path
    mobile_password_pattern = r'(final password = queryParameters\["password"\];)'

    mobile_token_code = '''final password = queryParameters["password"];
    final token = queryParameters["token"];

    // Token handling for mobile
    String? resolvedPassword = password;
    if (token != null && token.isNotEmpty && (password == null || password.isEmpty)) {
      resolvedPassword = 'TOKEN:$token';
    }'''

    if mobile_password_pattern in content or re.search(mobile_password_pattern, content):
        content = re.sub(mobile_password_pattern, mobile_token_code, content, count=1)
        # Also need to replace password usage with resolvedPassword in mobile path
        # This is more complex, so for MVP we'll handle it in connect()
        print("Modified password extraction for mobile")

    # Write modified content
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"Successfully patched {filepath}")
    return True


def patch_connect_function(filepath='flutter/lib/common.dart'):
    """Patch the connect function to resolve TOKEN: prefix"""

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Check if already patched
    if 'TOKEN:' in content and 'resolveTokenToPassword' in content:
        # Find the connect function and add token resolution
        # Look for: connect(BuildContext context, String id,
        connect_pattern = r'(connect\(BuildContext context, String id,[\s\S]*?{)'

        token_resolution = '''connect(BuildContext context, String id,
    {bool isFileTransfer = false,
    bool isViewCamera = false,
    bool isTerminal = false,
    bool isTcpTunneling = false,
    bool isRDP = false,
    bool forceRelay = false,
    String? password,
    String? connToken,
    bool? isSharedPassword}) async {
  // Token resolution - if password starts with TOKEN:, resolve it
  if (password != null && password.startsWith('TOKEN:')) {
    final token = password.substring(6); // Remove 'TOKEN:' prefix
    debugPrint('Resolving token before connect...');
    final resolved = await resolveTokenToPassword(token);
    if (resolved != null) {
      password = resolved;
    } else {
      // Token resolution failed - show error
      showToast('Failed to resolve connection token. Please try again.');
      return;
    }
  }
'''

        # Check if connect function signature matches
        match = re.search(r'connect\(BuildContext context, String id,', content)
        if match:
            # Find the opening brace of the function
            brace_pos = content.find('{', match.start())
            if brace_pos != -1:
                # Find the async keyword position
                async_check = content[match.start():brace_pos]
                if 'async' in async_check:
                    # Already async, just add token resolution after the opening brace
                    # Find position after opening brace and any initial variable declarations
                    insert_pos = brace_pos + 1

                    # Add token resolution code
                    token_code = '''
  // Token resolution - if password starts with TOKEN:, resolve it
  if (password != null && password.startsWith('TOKEN:')) {
    final token = password.substring(6); // Remove 'TOKEN:' prefix
    debugPrint('Resolving token before connect...');
    final resolved = await resolveTokenToPassword(token);
    if (resolved != null) {
      password = resolved;
    } else {
      showToast('Failed to resolve connection token. Please try again.');
      return;
    }
  }
'''
                    content = content[:insert_pos] + token_code + content[insert_pos:]

                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)

                    print("Added token resolution to connect function")
                    return True

    print("Could not patch connect function - may need manual adjustment")
    return False


def add_json_import(filepath='flutter/lib/common.dart'):
    """Ensure dart:convert is imported for jsonDecode"""

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    if "import 'dart:convert'" not in content:
        # Add import at the top
        first_import = content.find("import '")
        if first_import != -1:
            content = content[:first_import] + "import 'dart:convert';\n" + content[first_import:]

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

            print("Added dart:convert import")
            return True
    else:
        print("dart:convert already imported")

    return True


def main():
    print(f"Token Auth Patch for RustDesk")
    print(f"Token API URL: {TOKEN_API_URL}")
    print("-" * 50)

    filepath = 'flutter/lib/common.dart'

    if not os.path.exists(filepath):
        print(f"Error: {filepath} not found")
        print("Make sure you're running this from the rustdesk root directory")
        sys.exit(1)

    # Apply patches
    success = True

    success = add_json_import(filepath) and success
    success = patch_common_dart(filepath) and success
    success = patch_connect_function(filepath) and success

    if success:
        print("-" * 50)
        print("Token authentication patch applied successfully!")
        print(f"RustDesk will resolve tokens via: {TOKEN_API_URL}/api/token/resolve/{{token}}")
    else:
        print("-" * 50)
        print("Some patches failed - check output above")
        sys.exit(1)


if __name__ == "__main__":
    main()
