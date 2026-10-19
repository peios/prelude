"""Import a target-matched static SDK without an ambient library search."""

def _sdk_repository_impl(ctx):
    sdk = ctx.os.environ.get("PEIOS_SDK")
    if not sdk or not sdk.startswith("/"):
        fail("Set PEIOS_SDK to an absolute directory containing include/, lib/libpeios.a and TARGET.")
    for name in ["include/peios.h", "include/pkm", "lib/libpeios.a", "TARGET"]:
        if not ctx.path(sdk + "/" + name).exists:
            fail("Missing static SDK input: " + sdk + "/" + name)
    triple = ctx.read(sdk + "/TARGET").strip()
    if triple not in ["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"]:
        fail("Unsupported static SDK target: " + triple)
    ctx.symlink(sdk + "/include", "include")
    ctx.symlink(sdk + "/lib/libpeios.a", "lib/libpeios.a")
    for name in ["SDK.json", "licenses"]:
        if ctx.path(sdk + "/" + name).exists:
            ctx.symlink(sdk + "/" + name, name)
    ctx.file("root", triple + "\n")
    ctx.file("TARGET", triple + "\n")
    constraint = str(ctx.attr.musl if triple.endswith("musl") else ctx.attr.gnu)
    ctx.file("BUILD.bazel", """
load("@rules_cc//cc:defs.bzl", "cc_import")
package(default_visibility = ["//visibility:public"])
exports_files(["root"])
filegroup(name = "files", srcs = glob(["include/**", "lib/**", "licenses/**", "SDK.json", "TARGET"]))
cc_import(
    name = "peios",
    static_library = "lib/libpeios.a",
    hdrs = glob(["include/**"]),
    includes = ["include"],
    target_compatible_with = ["%s"],
)
""" % constraint)

sdk_repository = repository_rule(
    implementation = _sdk_repository_impl,
    attrs = {
        "gnu": attr.label(default = Label("//build:libc-gnu")),
        "musl": attr.label(default = Label("//build:libc-musl")),
    },
    local = True,
    configure = True,
    environ = ["PEIOS_SDK"],
)
