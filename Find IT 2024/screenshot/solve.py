import subprocess

with open('dnstwist.txt', 'r') as file:
    urls = file.readlines()

for url in urls:
    url = url.strip()
    if url:
        try:
            result = subprocess.run(['curl', '-s', url], capture_output=True, text=True)
            print(f'Success: Received response from {url}')
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f'Error: Curl failed for {url}. Exception: {e}')