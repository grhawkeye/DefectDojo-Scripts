import configparser
import requests
import json
import os
import xml.etree.ElementTree as ET

class DefectDojoImporter:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = 'http://127.0.0.1:8080'

    def get_auth_token(self, username, password):
        url = f"{self.base_url}/api/v2/api-token-auth/"
        data = {'username': username, 'password': password}
        response = self.session.post(url, data=data)
        if response.status_code == 200:
            token = response.json()['token']
            with open('auth_token.json', 'w') as f:
                json.dump({'token': token}, f)
            return token
        else:
            raise Exception(f"Authentication failed: {response.status_code} - {response.content}")

    def set_auth_token(self, token):
        self.session.headers.update({'Authorization': f'Token {token}'})

    def get_product_type_id(self, product_type_name):
        """Find the product type ID by name."""
        url = f"{self.base_url}/api/v2/product_types/"
        params = {'name': product_type_name}
        response = self.session.get(url, params=params)
        if response.status_code == 200 and response.json()['results']:
            return response.json()['results'][0]['id']
        raise Exception(f"Product type '{product_type_name}' not found in DefectDojo")

    def get_product_id(self, product_type_name, product_name):
        """Find or create a product by name under the specified product type."""
        # Get product type ID
        prod_type_id = self.get_product_type_id(product_type_name)
        
        # Check if product exists
        url = f"{self.base_url}/api/v2/products/"
        params = {'name': product_name}
        response = self.session.get(url, params=params)
        if response.status_code == 200 and response.json()['results']:
            for product in response.json()['results']:
                if product['prod_type'] == prod_type_id:
                    return product['id']
        
        # Create new product
        data = {
            'name': product_name,
            'prod_type': prod_type_id,
            'description': 'Automatically created by import script'  # Required field
        }
        response = self.session.post(url, data=data)
        if response.status_code == 201:
            return response.json()['id']
        raise Exception(f"Failed to create/find product: {response.status_code} - {response.content}")

    def get_engagement_id(self, product_id, engagement_name):
        """Find an engagement by name under the specified product."""
        url = f"{self.base_url}/api/v2/engagements/"
        params = {'product': product_id, 'name': engagement_name}
        response = self.session.get(url, params=params)
        if response.status_code == 200 and response.json()['results']:
            return response.json()['results'][0]['id']
        return None

    def get_latest_test_id(self, engagement_id, scan_type):
        """Find the latest test ID for the given scan_type in the engagement."""
        url = f"{self.base_url}/api/v2/tests/"
        params = {'engagement': engagement_id, 'test_type_name': scan_type}
        response = self.session.get(url, params=params)
        if response.status_code == 200 and response.json()['results']:
            # Sort by updated date to get the latest test
            tests = sorted(response.json()['results'], key=lambda x: x['updated'], reverse=True)
            return tests[0]['id']
        return None

    def import_scan(self, xml_file_path, product_type_name, product_name, engagement_name):
        """Initial import of a scan report."""
        url = f"{self.base_url}/api/v2/import-scan/"
        with open(xml_file_path, 'rb') as f:
            data = {
                'scan_type': 'HCL AppScan on Cloud SAST XML',
                'product_type_name': product_type_name,
                'product_name': product_name,
                'engagement_name': engagement_name,
                'auto_create_context': 'true',
                'deduplication_on_engagement': 'false',
                'close_old_findings': 'false'
            }
            files = {'file': f}
            response = self.session.post(url, data=data, files=files)
            if response.status_code == 201:
                print(f"Successfully imported {xml_file_path}")
                # print(f"Import statistics: {response.json().get('statistics', {})}")
            else:
                print(f"Failed to import {xml_file_path}: {response.status_code} - {response.content}")

    def reimport_scan(self, xml_file_path, test_id, product_type_name, product_name, engagement_name):
        """Reimport a scan report into an existing test."""
        url = f"{self.base_url}/api/v2/reimport-scan/"
        with open(xml_file_path, 'rb') as f:
            data = {
                'scan_type': 'HCL AppScan on Cloud SAST XML',
                'product_type_name': product_type_name,
                'product_name': product_name,
                'engagement_name': engagement_name,
                'test': test_id,
                'auto_create_context': 'true',
                'deduplication_on_engagement': 'false',
                'close_old_findings': 'false',
                'do_not_reactivate': 'true'
            }
            files = {'file': f}
            response = self.session.post(url, data=data, files=files)
            if response.status_code == 201:
                print(f"Successfully reimported {xml_file_path} into test ID {test_id}")
                # print(f"Reimport statistics: {response.json().get('statistics', {})}")
            else:
                print(f"Failed to reimport {xml_file_path}: {response.status_code} - {response.content}")

def extract_xml_data(xml_file_path):
    """Extract product_name and engagement_name from the XML file."""
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        
        # Extract application-name for product_name
        application_name = root.find('.//application-name')
        product_name = application_name.text if application_name is not None else None
        
        # Extract asoc-scan-name for engagement_name
        asoc_scan_name = root.find('.//asoc-scan-name')
        engagement_name = asoc_scan_name.text if asoc_scan_name is not None else None
        
        if not product_name:
            raise ValueError(f"Could not find <application-name> in {xml_file_path}")
        if not engagement_name:
            raise ValueError(f"Could not find <asoc-scan-name> in {xml_file_path}")
            
        return product_name, engagement_name
    except ET.ParseError as e:
        raise ValueError(f"Failed to parse XML file {xml_file_path}: {str(e)}")

def main():
    # Load credentials and configuration from settings.ini
    config = configparser.ConfigParser()
    if not os.path.exists('settings.ini'):
        raise FileNotFoundError("settings.ini file not found in the script directory")
    config.read('settings.ini')

    # Initialize the importer
    importer = DefectDojoImporter()

    # Authentication
    try:
        api_key = config['credentials']['api_key']
        token_data = {'token': api_key}
        with open('auth_token.json', 'w') as f:
            json.dump(token_data, f)
        importer.set_auth_token(api_key)
    except KeyError:
        try:
            username = config['credentials']['username']
            password = config['credentials']['password']
            token = importer.get_auth_token(username, password)
            importer.set_auth_token(token)
        except KeyError:
            raise KeyError("Missing 'api_key' or 'username' and 'password' in settings.ini")

    # Read product_type_name from settings.ini
    try:
        product_type_name = config['configuration']['product_type_name']
    except KeyError:
        raise KeyError("Missing 'product_type_name' in settings.ini under [configuration]")

    # Process XML files
    reports_dir = 'asoc_sast_reports'
    if not os.path.exists(reports_dir):
        raise FileNotFoundError(f"Directory {reports_dir} not found")
    
    xml_files = [f for f in os.listdir(reports_dir) if f.endswith('.xml')]
    if not xml_files:
        print(f"No XML files found in {reports_dir}")
        return

    for xml_file in xml_files:
        xml_file_path = os.path.join(reports_dir, xml_file)
        try:
            # Extract product_name and engagement_name from XML
            product_name, engagement_name = extract_xml_data(xml_file_path)
            print(f"Processing {xml_file}: Product={product_name}, Engagement={engagement_name}")

            # Find or create product
            product_id = importer.get_product_id(product_type_name, product_name)

            # Check if engagement exists
            engagement_id = importer.get_engagement_id(product_id, engagement_name)

            if engagement_id:
                # Check for existing test
                test_id = importer.get_latest_test_id(engagement_id, 'HCL AppScan on Cloud SAST XML')
                if test_id:
                    # Reimport into existing test
                    importer.reimport_scan(xml_file_path, test_id, product_type_name, product_name, engagement_name)
                else:
                    # No test found, perform initial import
                    importer.import_scan(xml_file_path, product_type_name, product_name, engagement_name)
            else:
                # No engagement found, perform initial import
                importer.import_scan(xml_file_path, product_type_name, product_name, engagement_name)
        except ValueError as e:
            print(f"Error processing {xml_file}: {str(e)}")
            continue
        except Exception as e:
            print(f"Unexpected error processing {xml_file}: {str(e)}")
            continue

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {str(e)}")