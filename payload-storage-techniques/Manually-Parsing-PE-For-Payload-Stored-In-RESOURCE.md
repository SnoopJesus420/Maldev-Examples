## Manually Parsing a PE Resource Directory Tree

Let’s break down how the PE (Portable Executable) resource directory tree is manually parsed to locate an RCDATA blob by ID and retrieve its raw bytes. This process involves navigating the PE file structure, used by Windows executables and DLLs to store resources like icons, strings, and custom data (e.g., RCDATA).

### Background on PE Resources
The PE file format includes a resource section that organizes resources in a hierarchical tree structure. This tree has multiple levels:
- **Level 1 (Type)**: Defines the type of resource (e.g., RT_RCDATA = 10 for raw data).
- **Level 2 (Name/ID)**: Identifies the specific resource by name or ID.
- **Level 3 (Language)**: Specifies the language (e.g., English, neutral) of the resource.
- **Data**: Contains the actual resource data (e.g., the raw bytes of the RCDATA blob).

The resource directory is stored in the `.rsrc` section of the PE file, and its layout is defined by structures like `IMAGE_RESOURCE_DIRECTORY`, `IMAGE_RESOURCE_DIRECTORY_ENTRY`, and `IMAGE_RESOURCE_DATA_ENTRY`.

### Step-by-Step Explanation

#### 1. **Setup and Initial Validation**
- The function starts with a pointer `base` to the loaded PE file in memory.
- It casts `base` to a `PIMAGE_DOS_HEADER` (the DOS header) and checks the `e_magic` field. This should be `IMAGE_DOS_SIGNATURE` (0x5A4D) to confirm it's a valid DOS header.
- It then moves to the NT headers by adding `dos->e_lfanew` (an offset) to `base` and casts it to `PIMAGE_NT_HEADERS`. The `Signature` field is checked to ensure it’s `IMAGE_NT_SIGNATURE` (0x00004550), confirming a valid PE file.
- The first section header (`IMAGE_SECTION_HEADER`) is accessed to find the virtual address of the resource section (`section->VirtualAddress`). This gives us `resbase`, the starting point of the resource data in memory.

#### 2. **Level 1: Finding the RCDATA Type**
- The resource directory root is located at `resbase + 1` (the `+1` accounts for the directory structure's layout).
- This is cast to `PIMAGE_RESOURCE_DIRECTORY`, which contains the root of the resource tree.
- We’re looking for the RCDATA type, which has an ID of 10 (`RT_RCDATA_NUM`). The directory has entries for named and ID-based resources, with a total count in `NumberOfNamedEntries + NumberOfIdEntries`.
- We iterate through the `DirectoryEntries` array. Each entry (`IMAGE_RESOURCE_DIRECTORY_ENTRY`) has a `NameIsString` flag and an `Id` field. If `NameIsString` is false and `Id` matches 10, we’ve found the RCDATA type entry.
- The `OffsetToDirectory` in this entry points to the next level (Level 2), stored relative to `resbase`.

#### 3. **Level 2: Finding the Resource by ID**
- Using the `OffsetToDirectory` from the RCDATA entry, we calculate the address of the next directory (`nameDir`) by adding it to `resbase`.
- We now look for the specific resource ID provided as an argument (`id`). Again, we iterate through the directory entries.
- If an entry’s `Id` matches the input `id` (and `NameIsString` is false), we get its `OffsetToDirectory` to proceed to Level 3.

#### 4. **Level 3: Finding the Language**
- The `OffsetToDirectory` from the ID entry gives us the address of the language directory (`langDir`) when added to `resbase`.
- Typically, this level contains a single entry for the default language (e.g., neutral). We access the `IMAGE_RESOURCE_DATA_ENTRY` that follows the directory structure (at `langDir + 1`).
- This data entry provides the `OffsetToData` (relative to `base`) and `Size` of the resource data.

#### 5. **Retrieving the Raw Data**
- The final data pointer is calculated by adding `dataEntry->OffsetToData` to `base`, giving the memory address of the raw RCDATA bytes.
- The `outSize` parameter is set to `dataEntry->Size` to return the size of the data.
- The function returns this pointer, or `NULL` if any step fails (e.g., invalid signatures or unmatched IDs).

### Key Structures Involved
- **`IMAGE_DOS_HEADER`**: Contains the initial magic number and offset to NT headers.
- **`IMAGE_NT_HEADERS`**: Includes the PE signature and section table.
- **`IMAGE_SECTION_HEADER`**: Describes each section (e.g., `.rsrc`).
- **`IMAGE_RESOURCE_DIRECTORY`**: The root or subdirectory of the resource tree, with entry counts.
- **`IMAGE_RESOURCE_DIRECTORY_ENTRY`**: An entry pointing to the next level or data.
- **`IMAGE_RESOURCE_DATA_ENTRY`**: Holds the offset and size of the actual resource data.

### Challenges and Considerations
- **Memory Bounds**: The code assumes all offsets are valid. In practice, you’d need to ensure they don’t exceed the PE file’s memory range.
- **Alignment**: PE resources are aligned, so offsets must be handled carefully.
- **Multiple Languages**: This example assumes a single language entry. Real files might have multiple, requiring further iteration.


### Code Exmaple
```C
#include <windows.h>

// From https://www.linkedin.com/posts/mikegropp_storing-shellcode-in-the-resources-section-activity-7343608917098209281-Fwgx?utm_medium=ios_app&rcm=ACoAAD9e9ZcBf3ctE4ZQLxBwnrDd7saeZQPTjUk&utm_source=social_share_send&utm_campaign=copy_link 
// Converted from CPP to C

PVOID GetRcdata(uint8_t* base, uint32_t id, uint32_t* outSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    uint8_t* resbase = base + section->VirtualAddress;

    // Level 1: TYPE
    PIMAGE_RESOURCE_DIRECTORY root = (PIMAGE_RESOURCE_DIRECTORY)(resbase + 1);
    const WORD RT_RCDATA_NUM = 10;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY* rcdataDirEntry = NULL;
    WORD count = root->NumberOfNamedEntries + root->NumberOfIdEntries;
    for (WORD i = 0; i < count; ++i, ++rcdataDirEntry) {
        PIMAGE_RESOURCE_DIRECTORY_ENTRY entry = &root->DirectoryEntries[i];
        if (entry->NameIsString && entry->Id == RT_RCDATA_NUM) {
            rcdataDirEntry = &entry->Directory;
            break;
        }
    }
    if (!rcdataDirEntry) return NULL;

    // Level 2: NAME / ID
    PIMAGE_RESOURCE_DIRECTORY nameDir = resbase + rcdataDirEntry->OffsetToDirectory;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY* langDirEntry = NULL;
    count = nameDir->NumberOfNamedEntries + nameDir->NumberOfIdEntries;
    for (WORD i = 0; i < count; ++i, ++langDirEntry) {
        PIMAGE_RESOURCE_DIRECTORY_ENTRY entry = &nameDir->DirectoryEntries[i];
        if (entry->NameIsString && entry->Id == id) {
            langDirEntry = &entry->Directory;
            break;
        }
    }
    if (!langDirEntry) return NULL;

    // Level 3: LANGUAGE
    PIMAGE_RESOURCE_DIRECTORY langDir = resbase + langDirEntry->OffsetToDirectory;
    PIMAGE_RESOURCE_DATA_ENTRY dataDesc = (PIMAGE_RESOURCE_DATA_ENTRY)(langDir + 1);
    PIMAGE_RESOURCE_DATA_ENTRY dataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(resbase + dataDesc->OffsetToData);

    *outSize = dataEntry->Size;
    return (PVOID)(base + dataEntry->OffsetToData);
}
```
