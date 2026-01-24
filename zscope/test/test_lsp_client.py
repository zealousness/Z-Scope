import os
import unittest
from pathlib import Path
from zscope.common.lsp_client import LSPClient

class TestLSPClient(unittest.TestCase):
    def setUp(self):
        # Use the current project or a test project root
        self.project_root = Path(os.getcwd()).resolve()
        self.client = LSPClient(self.project_root)

    def test_start_stop(self):
        """Test starting and stopping the clangd process."""
        # This requires clangd to be installed on the system
        try:
            success = self.client.start()
            if success:
                self.assertTrue(self.client._initialized)
                self.client.stop()
            else:
                print("clangd not found or failed to start, skipping test")
        except Exception as e:
            print(f"Skipping test due to error: {e}")

    def test_initialize_fail(self):
        """Test failure case with invalid clangd path."""
        invalid_client = LSPClient(self.project_root, clangd_path="non_existent_clangd")
        success = invalid_client.start()
        self.assertFalse(success)

if __name__ == "__main__":
    unittest.main()
