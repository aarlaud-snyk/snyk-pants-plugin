from pants.task.task import Task
import sys, os


def craftPomFile(listOfDeps):    
    import xml.etree.cElementTree as ET
    project = ET.Element("project")

    ET.SubElement(project, "modelVersion").text = "4.0.0"
    parent = ET.SubElement(project, "parent")
    ET.SubElement(parent, "artifactId").text = "io.snyk.example"
    ET.SubElement(parent, "groupId").text = "parent"
    ET.SubElement(parent, "version").text = "1.0-SNAPSHOT"

    ET.SubElement(project, "artifactId").text = "my-project"

    dependencies = ET.SubElement(project, "dependencies")
    for dep in listOfDeps:
        dependency = ET.SubElement(dependencies, "dependency")
        ET.SubElement(dependency, "groupId").text = dep['org']
        ET.SubElement(dependency, "artifactID").text = dep['name']
        ET.SubElement(dependency, "version").text = dep['rev']

    return ET.tostring(project, encoding='utf8').decode('utf8')


def craftRequirementsFile(listOfDeps):    
    import xml.etree.cElementTree as ET
    project = ET.Element("project")

    ET.SubElement(project, "modelVersion").text = "4.0.0"
    parent = ET.SubElement(project, "parent")
    ET.SubElement(parent, "artifactId").text = "io.snyk.example"
    ET.SubElement(parent, "groupId").text = "parent"
    ET.SubElement(parent, "version").text = "1.0-SNAPSHOT"

    ET.SubElement(project, "artifactId").text = "my-project"

    dependencies = ET.SubElement(project, "dependencies")
    for dep in listOfDeps:
        dependency = ET.SubElement(dependencies, "dependency")
        ET.SubElement(dependency, "groupId").text = dep['org']
        ET.SubElement(dependency, "artifactID").text = dep['name']
        ET.SubElement(dependency, "version").text = dep['rev']

    return ET.tostring(project, encoding='utf8').decode('utf8')

def snykAPITest(file, packageManager):
    import requests, os
    orgID = os.environ['SNYK_ORG']
    snyk_api_base_url = 'https://snyk.io/api/v1/'
    if 'SNYK_API' in os.environ:
        print('Hitting non standard API base url')
        snyk_api_base_url = os.environ['SNYK_API']
    snyk_api_headers = {
        'Authorization': 'token %s' % os.environ['SNYK_TOKEN']
    }
    snyk_post_api_headers = snyk_api_headers
    snyk_post_api_headers['Content-type'] = 'application/json'
    snyk_endpoint_url = ''
    obj_json_post_body = ''
    if packageManager == 'jvm':
        snyk_maven_package_endpoint = "test/maven?org={0}&repository=https%3A%2F%2Frepo1.maven.org%2Fmaven2".format(orgID)
        snyk_endpoint_url = snyk_api_base_url + snyk_maven_package_endpoint
    
        obj_json_post_body = {
            "encoding": "plain",
            "files": {
                "target": {
                    "contents": file
                }
            } 
        }
    if packageManager == 'pip':
        snyk_pip_req_endpoint = "test/pip?org={0}".format(orgID)
        snyk_endpoint_url = snyk_api_base_url + snyk_pip_req_endpoint   
        obj_json_post_body = {
            "encoding": "plain",
            "files": {
                "target": {
                    "contents": file
                }
            } 
        }
    resp = requests.post(snyk_endpoint_url, json=obj_json_post_body, headers=snyk_post_api_headers)
    return resp

def printSnykResults(rawResponse, isOutputJSON):
    if isOutputJSON:
        print(rawResponse)
    else: 
        import json
        jsonResponse = json.loads(rawResponse)
        print('Tested %d dependencies' % jsonResponse['dependencyCount'])
        print('Found %d issues' % (len(jsonResponse['issues']['vulnerabilities'])+len(jsonResponse['issues']['licenses'])))

        if len(jsonResponse['issues']['vulnerabilities']) > 0:
            print(jsonResponse['issues']['vulnerabilities'])
        if len(jsonResponse['issues']['licenses']) > 0:
            print(jsonResponse['issues']['licenses'])

class SnykTask(Task):
    

    @classmethod
    def register_options(cls, register):
        super(SnykTask, cls).register_options(register)
        # register('--my-option', type=bool, fingerprint=True,
        #      help='Path to the checkstyle configuration file.')
        register('--json', type=bool, fingerprint=True, default=False,
                help='Outputs json')

    def __init__(self, *args, **kwargs):
        super(SnykTask, self).__init__(*args, **kwargs)
        self.json = self.get_options().json
        
    @classmethod
    def prepare(cls, options, round_manager):
        super(SnykTask, cls).prepare(options, round_manager)
        round_manager.require_data('dependencies')

    def execute(self):

        if 'SNYK_ORG' not in os.environ or 'SNYK_TOKEN' not in os.environ:
            print('Setup your Snyk org ID in SNYK_ORG env var') 
            print('Setup your Snyk Token in SNYK_TOKEN env var')
            exit(1)

        print('\n')
        print('******************************************')
        print('*         CAUTION - DISCLAIMER           *')
        print('******************************************')
        print('Snyk Pants plugin - experimental and NOT officially supported by Snyk')
        print('Fully open source plugin using Snyk\'s APIs available for paid accounts.')
        print('Repo is on github.com/aarlaud-snyk/snyk-pants-plugin.')
        print('******************************************')
        print('*         /CAUTION - DISCLAIMER          *')
        print('******************************************')
        print('\n')
        print('Now extracting dependencies for target and comparing to Snyk DB')
        print('\n')

        # Get dependencies from dependencies task
        javaDeps = self.context.products.get_data('javaDependencies')
        pythonDeps = self.context.products.get_data('pythonDependencies')
        if len(javaDeps) > 0:
            pomFile = craftPomFile(javaDeps)
            snykResults = snykAPITest(pomFile, "jvm")
            printSnykResults(snykResults.text, self.json)
        if len(pythonDeps) > 0:
            requirementsFile = '\n'.join(pythonDeps)
            snykResults = snykAPITest(requirementsFile, "pip")
            printSnykResults(snykResults.text, self.json)