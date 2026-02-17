
import os

files = ["install.sh", "menu.sh", "docker-run.sh"]

for filename in files:
    if os.path.exists(filename):
        print(f"Fixing line endings for {filename}...")
        with open(filename, 'rb') as f:
            content = f.read()
        
        # Replace CRLF with LF
        content = content.replace(b'\r\n', b'\n')
        
        with open(filename, 'wb') as f:
            f.write(content)
        print(f"Done: {filename}")
