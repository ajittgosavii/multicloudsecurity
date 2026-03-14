import json
from typing import Dict, List


class AISecurityAnalyzer:
    """Uses AWS Bedrock to analyze vulnerabilities and suggest remediation."""

    MODELS = [
        "anthropic.claude-3-sonnet-20240229-v1:0",
        "anthropic.claude-3-haiku-20240307-v1:0",
        "anthropic.claude-v2",
        "amazon.titan-text-express-v1",
    ]

    def __init__(self, clients):
        self.bedrock = clients['bedrock-runtime']

    def analyze(self, vulnerability: Dict, resource: Dict) -> Dict:
        prompt = self._build_prompt(vulnerability, resource)
        try:
            model = self.MODELS[0]
            if "claude-3" in model:
                return self._call_claude3(model, prompt, vulnerability)
            elif "claude" in model:
                return self._call_claude2(model, prompt, vulnerability)
            elif "titan" in model:
                return self._call_titan(model, prompt, vulnerability)
            return self._fallback(vulnerability)
        except Exception as exc:
            print(f"Bedrock error: {exc}")
            return self._fallback(vulnerability)

    # ------------------------------------------------------------------
    # Model callers
    # ------------------------------------------------------------------

    def _call_claude3(self, model, prompt, vuln):
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1000,
            "temperature": 0.1,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = self.bedrock.invoke_model(modelId=model, body=json.dumps(body))
        text = json.loads(resp['body'].read())['content'][0]['text']
        return self._parse(text, vuln)

    def _call_claude2(self, model, prompt, vuln):
        body = {
            "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
            "max_tokens_to_sample": 1000,
            "temperature": 0.1,
        }
        resp = self.bedrock.invoke_model(modelId=model, body=json.dumps(body))
        text = json.loads(resp['body'].read())['completion']
        return self._parse(text, vuln)

    def _call_titan(self, model, prompt, vuln):
        body = {
            "inputText": prompt,
            "textGenerationConfig": {"maxTokenCount": 1000, "temperature": 0.1},
        }
        resp = self.bedrock.invoke_model(modelId=model, body=json.dumps(body))
        text = json.loads(resp['body'].read())['results'][0]['outputText']
        return self._parse(text, vuln)

    # ------------------------------------------------------------------
    # Prompt / parsing
    # ------------------------------------------------------------------

    def _build_prompt(self, vuln: Dict, resource: Dict) -> str:
        return f"""You are a cloud security expert specializing in AWS.
Analyze this vulnerability and provide remediation steps.

VULNERABILITY:
- ID: {vuln.get('id', 'Unknown')}
- Title: {vuln.get('title', 'Unknown')}
- Severity: {vuln.get('severity', 'Unknown')}
- Description: {vuln.get('description', '')}

RESOURCE:
- Type: {resource.get('resource_type', 'Unknown')}
- ID: {resource.get('resource_id', 'Unknown')}
- Region: {resource.get('region', 'Unknown')}
- Details: {json.dumps(resource, indent=2, default=str)}

Return a JSON object with exactly these keys:
{{
    "risk_assessment": "string",
    "remediation_steps": ["step1", "step2"],
    "aws_commands": ["command1", "command2"],
    "impact": "string",
    "verification": ["check1", "check2"]
}}
Only respond with the JSON object."""

    def _parse(self, text: str, vuln: Dict) -> Dict:
        try:
            cleaned = text.strip()
            if cleaned.startswith('```json'):
                cleaned = cleaned[7:]
            if cleaned.endswith('```'):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            if cleaned.startswith('{'):
                parsed = json.loads(cleaned)
                required = ['risk_assessment', 'remediation_steps', 'aws_commands', 'impact', 'verification']
                if all(k in parsed for k in required):
                    return parsed
        except (json.JSONDecodeError, Exception):
            pass
        return self._fallback(vuln)

    def _fallback(self, vuln: Dict) -> Dict:
        vid = vuln.get('id', '')
        if 'SG-OPEN' in vid:
            return {
                'risk_assessment': 'Security group allows unrestricted access from the internet.',
                'remediation_steps': [
                    'Identify the overly permissive security group rules',
                    'Restrict source IP ranges to known CIDR blocks',
                    'Create a replacement security group if needed',
                ],
                'aws_commands': [
                    f'aws ec2 describe-security-group-rules --filter Name="group-id",Values="<sg-id>"',
                    'aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0',
                ],
                'impact': 'May disrupt access if source IPs are not properly configured.',
                'verification': ['Verify rules in AWS console', 'Test connectivity from authorized sources'],
            }
        if 'EC2-IMDS' in vid:
            return {
                'risk_assessment': 'IMDSv1 is enabled, exposing instance metadata to SSRF attacks.',
                'remediation_steps': [
                    'Require IMDSv2 on the instance',
                    'Update applications that rely on IMDSv1',
                ],
                'aws_commands': [
                    'aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled',
                ],
                'impact': 'Applications using IMDSv1 will need code changes.',
                'verification': ['Check metadata options in console', 'Test IMDSv2 token flow'],
            }
        return {
            'risk_assessment': f'Security issue: {vuln.get("title", "Unknown")}',
            'remediation_steps': [
                'Review AWS documentation for this resource type',
                'Implement security best practices',
                'Consult Security Hub for recommendations',
            ],
            'aws_commands': [],
            'impact': 'Requires security review and planning.',
            'verification': ['Check resource configuration in AWS console'],
        }
