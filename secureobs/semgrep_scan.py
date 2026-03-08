import subprocess
import os
import json
import requests
import sys

project_path = sys.argv[1]
api_url = sys.argv[2]
tenant_id = sys.argv[3]

'''
This script runs semgrep on a specified path and captures the output.
'''
def run_semgrep(path):
    '''
    Runs semgrep with the specified configuration on the given path.
    '''
    try:
        env = os.environ.copy()
        env['PYTHONUTF8'] = '1'  # Ensure UTF-8 encoding for subprocess output
        result = subprocess.run(['semgrep', '--config', 'p/ci','--json', path], capture_output=True, text=True, encoding='utf-8', env=env)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running semgrep: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Semgrep is not installed or not found in PATH.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def parse_semgrep_output(raw_json):
    '''
    This method parses the raw JSON output from semgrep and returns a list of SemgrepFinding objects.
    '''
    try:
        data = json.loads(raw_json)
        results = data.get('results', [])
        response = []
        for result in results:
            response.append(SemgrepFinding(
                checkId=result.get('check_id', ''),
                path=result.get('path', ''),
                lines=result.get('extra', {}).get('lines', ''),
                severity=result.get('extra', {}).get('severity', ''),
                message=result.get('extra', {}).get('message', ''),
                cwe=result.get('extra', {}).get('cwe', []),
                owasp=result.get('extra', {}).get('owasp', []),
                tenantId= tenant_id
            ))
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []
    return response


def send_to_api(findings):
    '''
    This method sends the findings to an API endpoint.
    '''
    url = api_url
    headers = {
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps([finding.__dict__ for finding in findings]),verify=False)
        if response.status_code == 201:
            print("Findings have been successfully created in the database.")
        else:
            print(f"Failed to send findings to API. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending findings to API: {e}")

class SemgrepFinding:
    '''
    This class represents a Semgrep finding.
    '''
    def __init__(self, checkId, path, lines, severity, message, cwe, owasp, tenantId):
        self.checkId = checkId
        self.path = path
        self.lines = lines
        self.severity = severity
        self.message = message
        self.tenantId = tenantId
        self.cwe = cwe
        self.owasp = owasp

if __name__ == "__main__":
    # Specify the path to run semgrep on
    result = run_semgrep(project_path)
    if result:
        findings = parse_semgrep_output(result)
        send_to_api(findings)