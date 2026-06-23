import os

class FileNode:
    def __init__(self, name, is_directory=False, content="", owner="SYSTEM", writable_by=None, readable_by=None):
        self.name = name
        self.is_directory = is_directory
        self.content = content
        self.owner = owner
        # Groups/users allowed to write. If None, default is ["Administrators", "SYSTEM"]
        self.writable_by = writable_by if writable_by is not None else ["Administrators", "SYSTEM"]
        # Groups/users allowed to read. If None, default is ["Everyone"]
        self.readable_by = readable_by if readable_by is not None else ["Everyone"]
        self.children = {} if is_directory else None

class MockFilesystem:
    def __init__(self):
        # Build the root structure
        self.root = FileNode("C:", is_directory=True)
        self._initialize_default_filesystem()

    def _initialize_default_filesystem(self):
        # Create common Windows directories
        self.mkdir("C:\\Windows")
        self.mkdir("C:\\Windows\\System32")
        self.mkdir("C:\\Program Files")
        self.mkdir("C:\\Program Files\\Common Files")
        self.mkdir("C:\\Users")
        self.mkdir("C:\\Users\\labuser")
        self.mkdir("C:\\Users\\labuser\\Desktop")
        self.mkdir("C:\\Users\\labuser\\Documents")
        self.mkdir("C:\\Users\\Administrator")
        self.mkdir("C:\\Users\\Administrator\\Desktop")
        
        # Set specific folder permissions
        # Administrator Desktop: Only readable/writable by Admin/SYSTEM
        admin_desktop = self._get_node("C:\\Users\\Administrator\\Desktop")
        if admin_desktop:
            admin_desktop.readable_by = ["Administrators", "SYSTEM"]
            admin_desktop.writable_by = ["Administrators", "SYSTEM"]
            admin_desktop.owner = "Administrator"

        # Labuser Desktop/Documents: Writable by labuser
        for path in ["C:\\Users\\labuser", "C:\\Users\\labuser\\Desktop", "C:\\Users\\labuser\\Documents"]:
            node = self._get_node(path)
            if node:
                node.writable_by = ["labuser", "Administrators", "SYSTEM"]
                node.readable_by = ["labuser", "Administrators", "SYSTEM"]
                node.owner = "labuser"

        # Create basic files
        self.write_file("C:\\Windows\\System32\\cmd.exe", "[Binary Data: Command Prompt]", "SYSTEM")
        self.write_file("C:\\Windows\\System32\\whoami.exe", "[Binary Data: Whoami Utility]", "SYSTEM")
        self.write_file("C:\\Users\\labuser\\Desktop\\welcome.txt", "Welcome to the Windows Privilege Escalation Lab!\nUse the web dashboard on the left to read the guides and escalate your privileges.", "labuser")
        
    def _normalize_path(self, path):
        path = path.replace('/', '\\')
        # Remove trailing backslash if not C:\
        if len(path) > 3 and path.endswith('\\'):
            path = path[:-1]
        return path

    def _split_path(self, path):
        path = self._normalize_path(path)
        if not path.upper().startswith("C:"):
            return None
        parts = path.split('\\')
        # parts[0] is 'C:' or 'c:'
        parts[0] = "C:"
        return [p for p in parts if p]

    def _get_node(self, path):
        parts = self._split_path(path)
        if not parts:
            return None
        
        curr = self.root
        for part in parts[1:]:
            if not curr.is_directory or part not in curr.children:
                return None
            curr = curr.children[part]
        return curr

    def exists(self, path):
        return self._get_node(path) is not None

    def is_dir(self, path):
        node = self._get_node(path)
        return node is not None and node.is_directory

    def mkdir(self, path, user="SYSTEM"):
        parts = self._split_path(path)
        if not parts:
            return False, "Invalid path"
        
        # Walk to parent
        parent_parts = parts[:-1]
        new_dir_name = parts[-1]
        
        parent_path = "\\".join(parent_parts)
        parent_node = self._get_node(parent_path)
        if not parent_node:
            return False, f"Parent path {parent_path} does not exist"
        
        if not parent_node.is_directory:
            return False, f"{parent_path} is not a directory"
            
        # Check write permissions
        if not self.has_write_permission(parent_node, user):
            return False, "Access is denied"
            
        if new_dir_name in parent_node.children:
            return False, "A subdirectory or file already exists"
            
        parent_node.children[new_dir_name] = FileNode(new_dir_name, is_directory=True, owner=user)
        return True, ""

    def write_file(self, path, content, user="SYSTEM", writable_by=None, readable_by=None):
        parts = self._split_path(path)
        if not parts:
            return False, "Invalid path"
            
        parent_parts = parts[:-1]
        file_name = parts[-1]
        
        parent_path = "\\".join(parent_parts)
        parent_node = self._get_node(parent_path)
        if not parent_node:
            return False, f"Directory {parent_path} does not exist"
            
        if not parent_node.is_directory:
            return False, f"{parent_path} is not a directory"
            
        # Check permissions on parent if creating new file
        is_new = file_name not in parent_node.children
        if is_new:
            if not self.has_write_permission(parent_node, user):
                return False, "Access is denied"
        else:
            # Check permissions on the file itself if overwriting
            file_node = parent_node.children[file_name]
            if file_node.is_directory:
                return False, "Access is denied: Target is a directory"
            if not self.has_write_permission(file_node, user):
                return False, "Access is denied"
                
        # Write file
        parent_node.children[file_name] = FileNode(
            file_name, 
            is_directory=False, 
            content=content, 
            owner=user,
            writable_by=writable_by,
            readable_by=readable_by
        )
        return True, ""

    def read_file(self, path, user="labuser"):
        node = self._get_node(path)
        if not node:
            return None, "The system cannot find the file specified"
        if node.is_directory:
            return None, "Access is denied: Target is a directory"
        if not self.has_read_permission(node, user):
            return None, "Access is denied"
        return node.content, ""

    def delete_file(self, path, user="labuser"):
        parts = self._split_path(path)
        if not parts:
            return False, "Invalid path"
            
        parent_parts = parts[:-1]
        file_name = parts[-1]
        
        parent_path = "\\".join(parent_parts)
        parent_node = self._get_node(parent_path)
        if not parent_node:
            return False, "File not found"
            
        if file_name not in parent_node.children:
            return False, "File not found"
            
        file_node = parent_node.children[file_name]
        if file_node.is_directory:
            return False, "Access is denied: Target is a directory"
            
        if not self.has_write_permission(file_node, user):
            return False, "Access is denied"
            
        del parent_node.children[file_name]
        return True, ""

    def list_dir(self, path, user="labuser"):
        node = self._get_node(path)
        if not node:
            return None, "The system cannot find the path specified"
        if not node.is_directory:
            return None, "The directory name is invalid"
        if not self.has_read_permission(node, user):
            return None, "Access is denied"
            
        results = []
        for name, child in node.children.items():
            results.append({
                "name": name,
                "is_dir": child.is_directory,
                "size": len(child.content) if not child.is_directory else 0,
                "owner": child.owner
            })
        return results, ""

    def has_write_permission(self, node, user):
        if user in ["SYSTEM", "root"]:
            return True
        if user == "Administrator" and "Administrators" in node.writable_by:
            return True
        if "Everyone" in node.writable_by:
            return True
        if user in node.writable_by:
            return True
        return False

    def has_read_permission(self, node, user):
        if user in ["SYSTEM", "Administrator", "root"]:
            return True
        if "Everyone" in node.readable_by:
            return True
        if user in node.readable_by:
            return True
        return False

    def get_icacls_string(self, path):
        node = self._get_node(path)
        if not node:
            return "No such file or directory"
        
        perms = []
        # Build standard output representation for permissions
        # e.g. NT AUTHORITY\SYSTEM:(I)(F)
        #      BUILTIN\Administrators:(I)(F)
        #      BUILTIN\Users:(I)(RX)
        
        # SYSTEM
        perms.append("NT AUTHORITY\\SYSTEM:(F)")
        
        # Administrators
        if "Administrators" in node.writable_by:
            perms.append("BUILTIN\\Administrators:(F)")
        elif "Administrators" in node.readable_by:
            perms.append("BUILTIN\\Administrators:(RX)")
            
        # Users / Everyone / labuser
        if "Everyone" in node.writable_by or "labuser" in node.writable_by:
            perms.append("BUILTIN\\Users:(F)")
        elif "Everyone" in node.readable_by or "labuser" in node.readable_by:
            perms.append("BUILTIN\\Users:(RX)")
        else:
            perms.append("BUILTIN\\Users:(N)")
            
        return f"{self._normalize_path(path)} " + " ".join(perms)
