import subprocess
import json
import requests
import sys

project_path = sys.argv[1]
api_gitleaks_url = sys.argv[2]
output_path = sys.argv[3]
tenant_id = sys.argv[4]

def run_gitleaks(path):
    '''
    Runs gitleaks with the specified configuration on the given path.
    '''
    try:
        result = subprocess.run(['gitleaks', 'dir', '--report-format', 'json','--report-path', f"{output_path}\\gitleaks-report.json",path], capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running gitleaks: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Gitleaks is not installed or not found in PATH.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def parse_gitleaks_output(file_path):
    '''
    This method parses the raw JSON output from gitleaks and returns a list of GitleaksFinding objects.
    '''
    try:
        with open(file_path, 'r', encoding='utf-8') as finding:
            data = json.load(finding)
            response = []
            for finding in data:
                response.append(GitleaksFinding(
                    ruleId=finding.get('RuleID', ''),
                    description=finding.get('Description', ''),
                    file=finding.get('File', ''),
                    line=finding.get('StartLine', ''),
                    fingerprint=finding.get('Fingerprint', ''),
                    match=finding.get('Match', '')
                ))
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return []
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []
    return response



def send_to_api(findings):
    '''
    This method sends the findings to an API endpoint.
    '''
    response = requests.post(
        url=api_gitleaks_url,
        headers={"Content-Type": "application/json"},
        data=json.dumps([finding.__dict__ for finding in findings]),
        verify=False
    )
    print(f"API Response Status Code: {response.status_code}")
    print(f"API Response Text: {response.text}")


class GitleaksFinding:
    '''
    This class represents a Gitleaks finding.
    '''
    def __init__ (self, ruleId, description, file, line, fingerprint,match):
        self.ruleId = ruleId
        self.description = description
        self.file = file
        self.line = line
        self.fingerprint = fingerprint
        self.match = match

if __name__ == "__main__":
    run_gitleaks(project_path)
    response = parse_gitleaks_output(output_path)
    send_to_api(response)
