import pytest
from sigma.collection import SigmaCollection
from sigma.backends.cortexxdr import CortexXDRBackend

@pytest.fixture
def cortexxdr_backend():
    return CortexXDRBackend()

def test_cortexxdr_and_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                    ParentImage: valueB
                condition: sel
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 (action_process_image_path = "valueA" and 
 actor_process_image_path = "valueB")''']

def test_cortexxdr_or_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA
                sel2:
                    ParentImage: valueB
                condition: 1 of sel*
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 (action_process_image_path = "valueA" or 
 actor_process_image_path = "valueB")''']

def test_cortexxdr_and_or_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA1
                        - valueA2
                    ParentImage:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 ((action_process_image_path in ("valueA1", "valueA2")) and 
 (actor_process_image_path in ("valueB1", "valueB2")))''']

def test_cortexxdr_or_and_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA1
                    ParentImage: valueB1
                sel2:
                    Image: valueA2
                    ParentImage: valueB2
                condition: 1 of sel*
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 ((action_process_image_path = "valueA1" and 
 actor_process_image_path = "valueB1") or 
 (action_process_image_path = "valueA2" and 
 actor_process_image_path = "valueB2"))''']

def test_cortexxdr_in_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 (action_process_image_path in ("valueA", "valueB", "valueC*"))''']

def test_cortexxdr_regex_query(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image|re: foo.*bar
                    ParentImage: foo
                condition: sel
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 (action_process_image_path ~= "foo.*bar" and 
 actor_process_image_path = "foo")''']

def test_cortexxdr_cidr_query(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    SourceIp|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['''config case_sensitive = false | preset=network_story | filter event_type = ENUM.NETWORK and 
 action_local_ip incidr "192.168.0.0/16"''']

def test_cortexxdr_default_output(cortexxdr_backend : CortexXDRBackend):
    """Test for output format default."""
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 action_process_image_path = "valueA"''']

def test_cortexxdr_json_output(cortexxdr_backend : CortexXDRBackend):
    """Test for output format json."""
    # TODO: implement a test for the output format
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """), "json"
    ) == {"queries":[{"query":'''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 action_process_image_path = "valueA"''', "title":"Test", "id":None, "description":None}]}

def test_cortexxdr_returned_fields(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
            fields:
                - Image
                - CommandLine
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 action_process_image_path = "valueA" | fields action_process_image_path,action_process_image_command_line''']

def test_cortexxdr_default_output_sigma_v2_tags(cortexxdr_backend: CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Sigma v2 Compatible Rule
            id: 11111111-1111-4111-8111-111111111111
            status: test
            description: Rule with Sigma v2 style metadata
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
            tags:
                - attack.execution
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 (agent_os_type = ENUM.AGENT_OS_WINDOWS and 
 action_process_image_path = "valueA")''']

def test_cortexxdr_default_output_sigma_v3_metadata(cortexxdr_backend: CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test Sigma v3 Compatible Rule
            id: 22222222-2222-4222-8222-222222222222
            status: stable
            description: Rule with Sigma v3 style metadata extensions
            references:
                - https://example.org/reference
            author: Test Author
            date: 2024-01-01
            modified: 2024-02-01
            level: medium
            falsepositives:
                - Administrator activity
            tags:
                - attack.t1059
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image|contains: bash
                condition: sel
        """)
    ) == ['''config case_sensitive = false | preset=xdr_process | filter (event_type = ENUM.PROCESS and 
 event_sub_type = ENUM.PROCESS_START) and 
 (agent_os_type = ENUM.AGENT_OS_LINUX and 
 action_process_image_path contains "bash")''']
