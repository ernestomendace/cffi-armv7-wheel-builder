import io
import json
import tarfile
import unittest

from verify_image_permissions import ImagePermissionError, inspect_image_archive


def layer(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, kind, payload, mode in entries:
            item = tarfile.TarInfo(name)
            item.uid = item.gid = 0
            item.mode = mode
            if kind == "dir":
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
            elif kind == "file":
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            else:
                item.type = tarfile.SYMTYPE
                item.linkname = payload
                archive.addfile(item)
    return output.getvalue()


def image_tar(changes=()):
    entries = [(name, "dir", b"", 0o755) for name in (
        "opt", "opt/codex-mcp", "opt/codex-mcp/bin",
        "opt/codex-mcp/lib", "opt/codex-mcp/lib/tools")]
    py = b"# valid Python\nVALUE = 1\n"
    entries.extend([
        ("opt/codex-mcp/bin/container-entrypoint.py", "file", py, 0o444),
        ("opt/codex-mcp/lib/tools/document_nas_docker_lease_port.py", "file", py, 0o444),
        ("opt/codex-mcp/lib/tools/document_nas_local_service_lease_v2.py", "file", py, 0o444),
    ])
    entries.extend(changes)
    layer_bytes = layer(entries)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        manifest = json.dumps([{"Config": "config.json", "RepoTags": ["test:latest"],
                                "Layers": ["layer.tar"]}]).encode()
        item = tarfile.TarInfo("manifest.json"); item.size = len(manifest)
        archive.addfile(item, io.BytesIO(manifest))
        config = b"{}"
        item = tarfile.TarInfo("config.json"); item.size = len(config)
        archive.addfile(item, io.BytesIO(config))
        item = tarfile.TarInfo("layer.tar"); item.size = len(layer_bytes)
        archive.addfile(item, io.BytesIO(layer_bytes))
    return output.getvalue()


class ImagePermissionTests(unittest.TestCase):
    def test_actual_layer_modes_allow_nonroot_entrypoint_and_cas_modules(self):
        result = inspect_image_archive(io.BytesIO(image_tar()))
        self.assertEqual(result, {"status":"PASS", "uid":61001, "gid":61001,
            "directories":5, "python_files":3, "cas_modules":2})

    def test_unreadable_entrypoint_is_rejected(self):
        change = ("opt/codex-mcp/bin/container-entrypoint.py", "file", b"x=1\n", 0o400)
        with self.assertRaisesRegex(ImagePermissionError, "IMAGE_RUNTIME_FILE_NOT_READABLE"):
            inspect_image_archive(io.BytesIO(image_tar([change])))

    def test_untraversable_parent_is_rejected(self):
        change = ("opt/codex-mcp", "dir", b"", 0o700)
        with self.assertRaisesRegex(ImagePermissionError, "IMAGE_DIRECTORY_NOT_TRAVERSABLE"):
            inspect_image_archive(io.BytesIO(image_tar([change])))

    def test_symlink_runtime_file_is_rejected(self):
        change = ("opt/codex-mcp/lib/tools/document_nas_docker_lease_port.py",
                  "symlink", "../../elsewhere", 0o777)
        with self.assertRaisesRegex(ImagePermissionError, "IMAGE_RUNTIME_FILE_IDENTITY_INVALID"):
            inspect_image_archive(io.BytesIO(image_tar([change])))

    def test_whiteout_removing_cas_module_is_rejected(self):
        change = ("opt/codex-mcp/lib/tools/.wh.document_nas_docker_lease_port.py",
                  "file", b"", 0)
        with self.assertRaisesRegex(ImagePermissionError, "IMAGE_RUNTIME_FILE_IDENTITY_INVALID"):
            inspect_image_archive(io.BytesIO(image_tar([change])))

    def test_invalid_python_file_is_rejected(self):
        change = ("opt/codex-mcp/lib/tools/document_nas_local_service_lease_v2.py",
                  "file", b"def broken(:\n", 0o444)
        with self.assertRaisesRegex(ImagePermissionError, "IMAGE_RUNTIME_MODULE_INVALID"):
            inspect_image_archive(io.BytesIO(image_tar([change])))


if __name__ == "__main__":
    unittest.main()
