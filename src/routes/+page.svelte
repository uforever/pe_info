<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from '@tauri-apps/plugin-dialog';
  import { Kbd, Badge, Card, Button, Modal, AccordionItem, Accordion, Table, TableBody, TableBodyCell, TableBodyRow, TableHead, TableHeadCell } from "flowbite-svelte";
  import { BanOutline, CheckOutline } from "flowbite-svelte-icons";

  let defaultModal = $state(false);
  let pe_info = $state(null);

  async function handleSubmit(event) {
    event.preventDefault();
    const file = await open({
      multiple: false,
      directory: false,
    });
    
    invoke('analyze', { filePath: file })
      .then((message) => {
        // console.log(message);
        pe_info = message;
        defaultModal= true;
      })
      .catch((error) => {
        pe_info = null;
        alert("Error:" + error);
      });
  }
</script>

<div class="flex justify-center items-center min-h-screen">
  <Card class="p-4 sm:p-6 md:p-8">
    <form class="flex flex-col space-y-6" onsubmit={handleSubmit}>
      <h3 class="text-xl font-medium text-gray-900 dark:text-white">PE info</h3>
      <Button type="submit" class="w-full">选择PE文件 (.exe/.dll)</Button>
    </form>
  </Card>
</div>

<Modal title="PE文件信息" form bind:open={defaultModal} size="xl">
  {#if pe_info}
  <Accordion flush>
    <AccordionItem open>
      {#snippet header()}基本信息{/snippet}
      <Table hoverable={true} border={false}>
        <TableBody>
          <TableBodyRow>
            <TableBodyCell>文件路径</TableBodyCell>
            <TableBodyCell>{pe_info.path}</TableBodyCell>
          </TableBodyRow>
          <TableBodyRow>
            <TableBodyCell>文件大小</TableBodyCell>
            <TableBodyCell>{`0x${pe_info.size.toString(16)} 字节`}</TableBodyCell>
          </TableBodyRow>
          <TableBodyRow>
            <TableBodyCell>架构</TableBodyCell>
            <TableBodyCell>{pe_info.is_x64 ? "64位" : "32位"}</TableBodyCell>
          </TableBodyRow>
          <TableBodyRow>
            <TableBodyCell>节区大小</TableBodyCell>
            <TableBodyCell>{pe_info.sections.length}</TableBodyCell>
          </TableBodyRow>
          <TableBodyRow>
            <TableBodyCell>导出函数数量</TableBodyCell>
            <TableBodyCell>{pe_info.export_table.length}</TableBodyCell>
          </TableBodyRow>
          <TableBodyRow>
            <TableBodyCell>导入库数量</TableBodyCell>
            <TableBodyCell>{pe_info.import_table.length}</TableBodyCell>
          </TableBodyRow>
        </TableBody>
      </Table>
    </AccordionItem>
    <AccordionItem>
      {#snippet header()}节表信息{/snippet}
      <Table striped={true}>
        <TableHead>
          <TableHeadCell>节区名</TableHeadCell>
          <TableHeadCell>原始指针</TableHeadCell>
          <TableHeadCell>RVA</TableHeadCell>
          <TableHeadCell>RV结尾</TableHeadCell>
        </TableHead>
        <TableBody>
          {#each pe_info.sections as section}
            <TableBodyRow>
              <TableBodyCell><Kbd>{section.name}</Kbd></TableBodyCell>
              <TableBodyCell>{`0x${section.ptr_raw_data.toString(16)}`}</TableBodyCell>
              <TableBodyCell>{`0x${section.rva.toString(16)}`}</TableBodyCell>
              <TableBodyCell>{`0x${section.rv_end.toString(16)}`}</TableBodyCell>
            </TableBodyRow>
          {/each}
        </TableBody>
      </Table>
    </AccordionItem>
    <AccordionItem>
      {#snippet header()}导出表信息{/snippet}
      {#if pe_info.export_table.length === 0}
        <p class="text-gray-500">无导出函数</p>
      {:else}
        <Table striped={true}>
          <TableHead>
            <TableHeadCell>序号</TableHeadCell>
            <TableHeadCell>地址</TableHeadCell>
            <TableHeadCell>函数名</TableHeadCell>
          </TableHead>
          <TableBody>
            {#each pe_info.export_table as exp}
              <TableBodyRow>
                <TableBodyCell>{exp.ordinal}</TableBodyCell>
                <TableBodyCell>{`0x${exp.address.toString(16)}`}</TableBodyCell>
                <TableBodyCell>{exp.name}</TableBodyCell>
              </TableBodyRow>
            {/each}
          </TableBody>
        </Table>
      {/if}
    </AccordionItem>
    <AccordionItem>
      {#snippet header()}导入表信息{/snippet}
      {#if pe_info.import_table.length === 0}
        <p class="text-gray-500">无导入库</p>
      {:else}
        {#each pe_info.import_table as imp}
          <Badge large border>{imp.dll_name}</Badge>
          <Table striped={true} class="mb-4">
            <TableHead>
              <TableHeadCell>函数名</TableHeadCell>
              <TableHeadCell>通过符号名导入</TableHeadCell>
              <TableHeadCell>序号</TableHeadCell>
              <TableHeadCell>Hint</TableHeadCell>
            </TableHead>
            <TableBody>
              {#each imp.functions as func}
                <TableBodyRow>
                  <TableBodyCell>{func.name}</TableBodyCell>
                  <TableBodyCell>
                    {#if func.is_ordinal}
                      <BanOutline class="shrink-0 h-5 w-5 text-red-500" />
                    {:else}
                      <CheckOutline class="shrink-0 h-5 w-5 text-green-500" />
                    {/if}
                  </TableBodyCell>
                  <TableBodyCell>{func.ordinal}</TableBodyCell>
                  <TableBodyCell>{func.hint}</TableBodyCell>
                </TableBodyRow>
              {/each}
            </TableBody>
          </Table>
        {/each}
      {/if}
    </AccordionItem>
  </Accordion>
  {:else}
    <p class="text-gray-500">无PE文件信息</p>
  {/if}
</Modal>