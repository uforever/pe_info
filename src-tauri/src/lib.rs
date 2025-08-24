// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use serde::{Deserialize, Serialize};

use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
struct Section {
    name: String,
    rva: u32,
    ptr_raw_data: u32,
    rv_end: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ImportFunction {
    name: String,
    is_ordinal: bool,
    ordinal: u16,
    hint: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct ExportFunction {
    name: String,
    ordinal: u32,
    address: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ImportTableEntry {
    dll_name: String,
    functions: Vec<ImportFunction>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PeInfo {
    path: String,
    size: u64,
    is_x64: bool,
    sections: Vec<Section>,
    export_table: Vec<ExportFunction>,
    import_table: Vec<ImportTableEntry>,
}

#[tauri::command]
fn analyze(file_path: &str) -> Result<PeInfo, String> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err("文件不存在".into());
    }

    // 打开文件
    let mut file = File::open(file_path).map_err(|e| format!("无法打开文件: {}", e))?;

    // 获取文件字节长度
    let size = file
        .metadata()
        .map_err(|e| format!("无法获取文件元数据: {}", e))?
        .len();
    // println!("文件大小: 0x{:X} 字节", size);

    let mut temp_byte_buffer = [0; 1];
    let mut temp_word_buffer = [0; 2];
    let mut temp_dword_buffer = [0; 4];
    let mut temp_qword_buffer = [0; 8];

    // 判断是否是PE文件
    // PE文件的前两个字节是"MZ"
    file.read_exact(&mut temp_word_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    if temp_word_buffer != [0x4D, 0x5A] {
        // eprintln!("不是有效的PE文件");
        // std::process::exit(1);
        return Err("不是有效的PE文件".into());
    }

    // 0x3C-0x3F是coff头的偏移位置
    file.seek(io::SeekFrom::Start(0x3C))
        .map_err(|e| format!("无法读取文件: {}", e))?;
    file.read_exact(&mut temp_dword_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    let coff_header_ptr = u32::from_le_bytes(temp_dword_buffer);
    // println!("COFF头偏移位置: 0x{:X}", coff_header_ptr);

    // 跳转到PE头位置
    file.seek(io::SeekFrom::Start(coff_header_ptr as u64))
        .map_err(|e| format!("无法读取文件: {}", e))?;
    file.read_exact(&mut temp_dword_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    if temp_dword_buffer != [0x50, 0x45, 0x00, 0x00] {
        // eprintln!("不是有效的PE文件");
        // std::process::exit(1);
        return Err("不是有效的PE文件".into());
    }

    // 读可选头的magic 判断是否为64为文件
    let magic_ptr = coff_header_ptr + 0x18;
    // println!("magic_ptr: 0x{:X}", magic_ptr);
    file.seek(io::SeekFrom::Start(magic_ptr as u64))
        .map_err(|e| format!("无法读取文件: {}", e))?;
    file.read_exact(&mut temp_word_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    let is_x64 = match u16::from_le_bytes(temp_word_buffer) {
        0x10B => false,
        0x20B => true,
        _ => {
            // eprintln!("未知的PE文件格式");
            // std::process::exit(1);
            return Err("未知的PE文件格式".into());
        }
    };
    // println!("架构: {}", if is_x64 { "x64" } else { "x86" });

    // 读取sizeof_optional_header
    let optional_header_size_ptr = coff_header_ptr + 0x14;
    file.seek(io::SeekFrom::Start(optional_header_size_ptr as u64))
        .map_err(|e| format!("无法读取文件: {}", e))?;
    file.read_exact(&mut temp_word_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    let optional_header_size = u16::from_le_bytes(temp_word_buffer);
    // println!("可选头大小: 0x{:X}", optional_header_size);
    let optional_header_ptr = coff_header_ptr + 0x18;
    // println!("可选头偏移位置: 0x{:X}", optional_header_ptr);

    // 读number_of_sections
    let number_of_sections_ptr = coff_header_ptr + 0x06;
    file.seek(io::SeekFrom::Start(number_of_sections_ptr as u64))
        .map_err(|e| format!("无法读取文件: {}", e))?;
    file.read_exact(&mut temp_word_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    let number_of_sections = u16::from_le_bytes(temp_word_buffer);
    // println!("节区数量: {}", number_of_sections);

    // 遍历节表信息
    let mut sections: Vec<Section> = Vec::with_capacity(number_of_sections as usize);
    // 节表偏移位置
    let section_table_ptr = optional_header_ptr + optional_header_size as u32;

    for i in 0..number_of_sections {
        let item_ptr = section_table_ptr + (i * 40) as u32;
        file.seek(io::SeekFrom::Start(item_ptr as u64))
            .map_err(|e| format!("无法读取文件: {}", e))?;
        file.read_exact(&mut temp_qword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let section_name = String::from_utf8_lossy(&temp_qword_buffer)
            .trim_end_matches('\0')
            .to_string();

        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let virtual_size = u32::from_le_bytes(temp_dword_buffer);

        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let rva = u32::from_le_bytes(temp_dword_buffer);

        let rv_end = rva + virtual_size;

        file.seek(io::SeekFrom::Start(item_ptr as u64 + 0x14))
            .map_err(|e| format!("无法读取文件: {}", e))?;
        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let ptr_raw_data = u32::from_le_bytes(temp_dword_buffer);

        sections.push(Section {
            name: section_name,
            rva,
            ptr_raw_data,
            rv_end,
        });
    }

    // println!("节表信息:");
    // println!(
    //     "{:<10} {:<12} {:<12} {:<12}",
    //     "名称", "原始地址", "RVA", "RV结束"
    // );
    // for section in &sections {
    //     println!(
    //         "{:<10}   0x{:08X}   0x{:08X}   0x{:08X}",
    //         section.name, section.ptr_raw_data, section.rva, section.rv_end
    //     );
    // }

    // 实现函数rva -> raw_ptr转换
    let relative_virtual_difference = |rva: u32| -> Option<u32> {
        for section in &sections {
            if rva >= section.rva && rva < section.rv_end {
                return Some(section.ptr_raw_data + (rva - section.rva));
            }
        }
        None
    };

    // 测试rva -> raw_ptr转换
    // let test_rva = 0x003BA1A4;
    // let test_raw_ptr = relative_virtual_difference(test_rva);
    // match test_raw_ptr {
    //     Some(ptr) => println!("RVA 0x{:08X} 对应的原始地址: 0x{:08X}", test_rva, ptr),
    //     None => println!("RVA 0x{:08X} 不在任何节区内", test_rva),
    // }

    // 获取导出表和导入表信息
    // 导出表在可选头的数据目录中第1个位置
    // 导入表在可选头的数据目录中第2个位置
    let data_directory_ptr = if is_x64 {
        optional_header_ptr + 0x70
    } else {
        optional_header_ptr + 0x60
    };
    // println!("数据目录偏移位置: 0x{:X}", data_directory_ptr);

    file.seek(io::SeekFrom::Start(data_directory_ptr as u64))
        .map_err(|e| format!("无法读取文件: {}", e))?;
    // 导出表rva
    file.read_exact(&mut temp_dword_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    let export_table_rva = u32::from_le_bytes(temp_dword_buffer);
    // 导出表size
    file.read_exact(&mut temp_dword_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    let export_table_size = u32::from_le_bytes(temp_dword_buffer);
    // 导入表rva
    file.read_exact(&mut temp_dword_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    let import_table_rva = u32::from_le_bytes(temp_dword_buffer);
    // 导入表size
    file.read_exact(&mut temp_dword_buffer)
        .map_err(|e| format!("无法读取文件: {}", e))?;
    let import_table_size = u32::from_le_bytes(temp_dword_buffer);

    // println!(
    //     "导出表 RVA: 0x{:08X}, 大小: 0x{:X}",
    //     export_table_rva, export_table_size
    // );

    let mut export_table: Vec<ExportFunction> = Vec::new();

    if export_table_size != 0 {
        // 导出表rva -> raw_ptr
        let export_table_ptr = match relative_virtual_difference(export_table_rva) {
            Some(ptr) => ptr,
            None => {
                // eprintln!("导出表RVA转换失败");
                // std::process::exit(1);
                return Err("导出表RVA转换失败".into());
            }
        };
        // println!("导出表偏移位置: 0x{:X}", export_table_ptr);
        // 读导出表的条目总数 和 以函数名导出的数量
        file.seek(io::SeekFrom::Start((export_table_ptr + 0x10) as u64))
            .map_err(|e| format!("无法读取文件: {}", e))?;
        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let ordinal_base = u32::from_le_bytes(temp_dword_buffer);
        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let addresses_amount = u32::from_le_bytes(temp_dword_buffer);
        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let name_pointers_amount = u32::from_le_bytes(temp_dword_buffer);

        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let address_table_rva = u32::from_le_bytes(temp_dword_buffer);
        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let name_pointer_table_rva = u32::from_le_bytes(temp_dword_buffer);
        file.read_exact(&mut temp_dword_buffer)
            .map_err(|e| format!("无法读取文件: {}", e))?;
        let ordinal_table_rva = u32::from_le_bytes(temp_dword_buffer);

        // rva全部转换成raw_ptr
        let address_table_ptr = match relative_virtual_difference(address_table_rva) {
            Some(ptr) => ptr,
            None => {
                // eprintln!("导出地址表RVA转换失败");
                // std::process::exit(1);
                return Err("导出地址表RVA转换失败".into());
            }
        };
        let name_pointer_table_ptr = match relative_virtual_difference(name_pointer_table_rva) {
            Some(ptr) => ptr,
            None => {
                // eprintln!("导出符号名表RVA转换失败");
                // std::process::exit(1);
                return Err("导出符号名表RVA转换失败".into());
            }
        };
        let ordinal_table_ptr = match relative_virtual_difference(ordinal_table_rva) {
            Some(ptr) => ptr,
            None => {
                // eprintln!("导出序号表RVA转换失败");
                // std::process::exit(1);
                return Err("导出序号表RVA转换失败".into());
            }
        };

        // 先把所有地址都push进去
        for i in 0..addresses_amount {
            file.seek(io::SeekFrom::Start((address_table_ptr + i * 4) as u64))
                .map_err(|e| format!("无法读取文件: {}", e))?;
            file.read_exact(&mut temp_dword_buffer)
                .map_err(|e| format!("无法读取文件: {}", e))?;
            let func_rva = u32::from_le_bytes(temp_dword_buffer);
            export_table.push(ExportFunction {
                name: String::new(),
                ordinal: 0,
                address: func_rva,
            });
        }

        // 读出所有名称
        let mut name_list: Vec<String> = Vec::with_capacity(name_pointers_amount as usize);
        for i in 0..name_pointers_amount {
            file.seek(io::SeekFrom::Start((name_pointer_table_ptr + i * 4) as u64))
                .map_err(|e| format!("无法读取文件: {}", e))?;
            file.read_exact(&mut temp_dword_buffer)
                .map_err(|e| format!("无法读取文件: {}", e))?;
            let name_rva = u32::from_le_bytes(temp_dword_buffer);
            let name_ptr = match relative_virtual_difference(name_rva) {
                Some(ptr) => ptr,
                None => {
                    name_list.push(String::new());
                    continue;
                }
            };
            // 读名称
            let mut func_name_bytes: Vec<u8> = Vec::new();
            file.seek(io::SeekFrom::Start(name_ptr as u64))
                .map_err(|e| format!("无法读取文件: {}", e))?;
            loop {
                file.read_exact(&mut temp_byte_buffer)
                    .map_err(|e| format!("无法读取文件: {}", e))?;
                if temp_byte_buffer[0] == 0 {
                    break;
                }
                func_name_bytes.push(temp_byte_buffer[0]);
            }
            let func_name = String::from_utf8_lossy(&func_name_bytes).to_string();
            name_list.push(func_name);
        }

        // 读出所有序号
        let mut ordinal_list: Vec<u16> = Vec::with_capacity(name_pointers_amount as usize);
        for i in 0..name_pointers_amount {
            file.seek(io::SeekFrom::Start((ordinal_table_ptr + i * 2) as u64))
                .map_err(|e| format!("无法读取文件: {}", e))?;
            file.read_exact(&mut temp_word_buffer)
                .map_err(|e| format!("无法读取文件: {}", e))?;
            let ordinal = u16::from_le_bytes(temp_word_buffer);
            ordinal_list.push(ordinal);
        }

        // 遍历ordinal_list
        for (i, &ordinal) in ordinal_list.iter().enumerate() {
            let name = name_list.get(i).cloned().unwrap_or_default();
            if let Some(func) = export_table.get_mut(i) {
                func.name = name;
                func.ordinal = ordinal as u32 + ordinal_base;
            }
        }
    }

    // 先通过序号排序
    export_table.sort_by_key(|f| f.ordinal);
    // println!("导出的函数:");
    // println!("{:<8} {:<10} 名称", "序号", "地址");

    // for func in &export_table {
    //     println!("{:<8} 0x{:08X} {}", func.ordinal, func.address, func.name);
    // }

    // println!(
    //     "导入表 RVA: 0x{:08X}, 大小: 0x{:X}",
    //     import_table_rva, import_table_size
    // );

    let mut import_table: Vec<ImportTableEntry> = Vec::new();

    if import_table_size != 0 {
        // 导入表rva -> raw_ptr
        let import_table_ptr = match relative_virtual_difference(import_table_rva) {
            Some(ptr) => ptr,
            None => {
                // eprintln!("导入表RVA转换失败");
                // std::process::exit(1);
                return Err("导入表RVA转换失败".into());
            }
        };
        // println!("导入表偏移位置: 0x{:X}", import_table_ptr);
        // 一个导入表项的大小是20字节
        let import_table_item_count = import_table_size / 20;
        // 遍历
        for i in 0..import_table_item_count {
            let import_table_item_ptr = import_table_ptr + (i * 20);
            // 读第一个字段 OriginalFirstThunk
            file.seek(io::SeekFrom::Start(import_table_item_ptr as u64))
                .map_err(|e| format!("无法读取文件: {}", e))?;
            file.read_exact(&mut temp_dword_buffer)
                .map_err(|e| format!("无法读取文件: {}", e))?;
            let lookup_table_rva = u32::from_le_bytes(temp_dword_buffer);
            let lookup_table_ptr = match relative_virtual_difference(lookup_table_rva) {
                Some(ptr) => ptr,
                None => {
                    continue;
                }
            };

            // 读第四个字段 Name
            file.seek(io::SeekFrom::Start(import_table_item_ptr as u64 + 12))
                .map_err(|e| format!("无法读取文件: {}", e))?;
            file.read_exact(&mut temp_dword_buffer)
                .map_err(|e| format!("无法读取文件: {}", e))?;
            let name_rva = u32::from_le_bytes(temp_dword_buffer);
            let name_ptr = match relative_virtual_difference(name_rva) {
                Some(ptr) => ptr,
                None => {
                    continue;
                }
            };

            // 读DLL名称
            let mut dll_name_bytes: Vec<u8> = Vec::new();
            file.seek(io::SeekFrom::Start(name_ptr as u64))
                .map_err(|e| format!("无法读取文件: {}", e))?;
            loop {
                file.read_exact(&mut temp_byte_buffer)
                    .map_err(|e| format!("无法读取文件: {}", e))?;
                if temp_byte_buffer[0] == 0 {
                    break;
                }
                dll_name_bytes.push(temp_byte_buffer[0]);
            }
            let dll_name = String::from_utf8_lossy(&dll_name_bytes).to_string();

            // println!("DLL名称: {}", dll_name);

            // 逐个读取函数名称和序号
            let mut functions: Vec<ImportFunction> = Vec::new();
            let mut lookup_item_ptr = lookup_table_ptr;
            let lookup_item_size = if is_x64 { 8 } else { 4 };

            loop {
                file.seek(io::SeekFrom::Start(lookup_item_ptr as u64))
                    .map_err(|e| format!("无法读取文件: {}", e))?;
                if is_x64 {
                    file.read_exact(&mut temp_qword_buffer)
                        .map_err(|e| format!("无法读取文件: {}", e))?;
                    let entry = u64::from_le_bytes(temp_qword_buffer);
                    if entry == 0 {
                        break;
                    }
                    let is_ordinal = (entry & 0x8000000000000000) != 0;
                    if is_ordinal {
                        let ordinal = (entry & 0xFFFF) as u16;
                        functions.push(ImportFunction {
                            name: String::new(),
                            is_ordinal: true,
                            ordinal,
                            hint: 0,
                        });
                    } else {
                        let hint_name_rva = (entry & 0x7FFFFFFFFFFFFFFF) as u32;
                        let hint_name_ptr = match relative_virtual_difference(hint_name_rva) {
                            Some(ptr) => ptr,
                            None => {
                                lookup_item_ptr += lookup_item_size;
                                continue;
                            }
                        };
                        // 读hint和name
                        file.seek(io::SeekFrom::Start(hint_name_ptr as u64))
                            .map_err(|e| format!("无法读取文件: {}", e))?;
                        file.read_exact(&mut temp_word_buffer)
                            .map_err(|e| format!("无法读取文件: {}", e))?;
                        let hint = u16::from_le_bytes(temp_word_buffer);
                        // 读名称
                        let mut func_name_bytes: Vec<u8> = Vec::new();
                        loop {
                            file.read_exact(&mut temp_byte_buffer)
                                .map_err(|e| format!("无法读取文件: {}", e))?;
                            if temp_byte_buffer[0] == 0 {
                                break;
                            }
                            func_name_bytes.push(temp_byte_buffer[0]);
                        }
                        let func_name = String::from_utf8_lossy(&func_name_bytes).to_string();
                        functions.push(ImportFunction {
                            name: func_name,
                            is_ordinal: false,
                            ordinal: 0,
                            hint,
                        });
                    }
                } else {
                    file.read_exact(&mut temp_dword_buffer)
                        .map_err(|e| format!("无法读取文件: {}", e))?;
                    let entry = u32::from_le_bytes(temp_dword_buffer);
                    if entry == 0 {
                        break;
                    }
                    let is_ordinal = (entry & 0x80000000) != 0;
                    if is_ordinal {
                        let ordinal = (entry & 0xFFFF) as u16;
                        functions.push(ImportFunction {
                            name: String::new(),
                            is_ordinal: true,
                            ordinal,
                            hint: 0,
                        });
                    } else {
                        let hint_name_rva = entry & 0x7FFFFFFF;
                        let hint_name_ptr = match relative_virtual_difference(hint_name_rva) {
                            Some(ptr) => ptr,
                            None => {
                                lookup_item_ptr += lookup_item_size;
                                continue;
                            }
                        };
                        // 读hint和name
                        file.seek(io::SeekFrom::Start(hint_name_ptr as u64))
                            .map_err(|e| format!("无法读取文件: {}", e))?;
                        file.read_exact(&mut temp_word_buffer)
                            .map_err(|e| format!("无法读取文件: {}", e))?;
                        let hint = u16::from_le_bytes(temp_word_buffer);
                        // 读名称
                        let mut func_name_bytes: Vec<u8> = Vec::new();
                        loop {
                            file.read_exact(&mut temp_byte_buffer)
                                .map_err(|e| format!("无法读取文件: {}", e))?;
                            if temp_byte_buffer[0] == 0 {
                                break;
                            }
                            func_name_bytes.push(temp_byte_buffer[0]);
                        }
                        let func_name = String::from_utf8_lossy(&func_name_bytes).to_string();
                        functions.push(ImportFunction {
                            name: func_name,
                            is_ordinal: false,
                            ordinal: 0,
                            hint,
                        });
                    }
                }
                lookup_item_ptr += lookup_item_size;
            }

            // 通过hint排序
            functions.sort_by_key(|f| f.hint);

            // println!("导入的函数:");
            // println!("{:<8} 名称", "序号");
            // for func in &functions {
            //     if func.ordinal != 0 {
            //         println!("{:<8} {}", func.ordinal, func.name);
            //     } else {
            //         println!("         {}", func.name);
            //     }
            // }

            import_table.push(ImportTableEntry {
                dll_name,
                functions,
            });
        }
    }

    let pe_info = PeInfo {
        path: String::from(file_path),
        size,
        is_x64,
        sections,
        export_table,
        import_table,
    };

    // let pe_info_json = serde_json::to_string(&pe_info).unwrap();
    // println!("PE信息(JSON):\n{}", pe_info_json);
    Ok(pe_info)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![analyze])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
