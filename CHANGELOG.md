# CHANGELOG.md

## 1.0.1 (2020-08-18)
  Fixes:
    - Fix for #1 accidentally introduced a bug where closing Ghidra without loading revsync would cause a null pointer dereference, due to Jedis never haven been started.
  
  Improvements:
    - Added console logging of client-side changes as they are sent to the redis server, similar to behavior of IDA Pro and Binary Ninja clients.

## 1.0.0 (2020-08-14)

Improvements:
  - Comments are now synced between EOL Comment, Pre Comment, Post Comment, and Plate Comment.
    - Pre comments are now the default instead of EOL comments, as they display in both Listing and Decompiler views without any change in configuration.
    - The behavior of comments now is for any comment put into a supported comment field to be moved into Pre Comment and deleted from the other comment fields. This allows smooth synchronizing with Binary Ninja and IDA Pro.
    - Repeatable comments are ignored and not supported.

Fixes:
  - Fixed #1 - null pointer dereference exception due to not closing Jedis connection correctly on program close.
  - Fixed issue where the presence of non-XML 1.0 characters in a comment would cause the decompiler to fail to render the function.
  - Fixed issue where deleted comments would show up as empty comment blocks in decompiler.

## 0.9 (2020-05-28)

Initial release