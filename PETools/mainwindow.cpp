#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


//选择文件按钮
void MainWindow::on_btnSelectFile_clicked()
{

    //    QString pathName = QFileDialog::getOpenFileName(this,tr("打开一个文件"),QDir::currentPath(),"PE文件(*.exe. *.dll)");
    //    QString pathName = QFileDialog::getOpenFileName(this,tr("打开一个文件"),QDir::currentPath(),"PE文件(*.exe)");
    //    QString pathName = "/Users/zhangjx/Documents/workspace/qt-demo/WeChat.exe";
    //    QString pathName = "/Users/zhangjx/Documents/workspace/qt-demo/notepad.exe";
    QString pathName = "/Users/zhangjx/Documents/workspace/qt-demo/mydll.dll";

    //QString pathName = "/Users/zhangjx/Documents/workspace/qt-demo/PE.exe";
    QFile file(pathName);
    if(!file.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(this,"错误","打开失败！！",QMessageBox::Ok,QMessageBox::Ok);
        return;
    }

    QFileInfo fileInfo(file);

    //用文本流读取文件
    QDataStream aStream(&file);

    //windows平台
    aStream.setByteOrder(QDataStream::LittleEndian);


    ui->textDesc->appendPlainText("文件位置：" + pathName );
    ui->textDesc->appendPlainText("文件大小：" + QString::number( fileInfo.size() ) + "byte");


    //读到数组中
    char charArray[fileInfo.size()];
    //    char* peArray ;
    aStream.readRawData(charArray, fileInfo.size());

    fileByteArray = QByteArray(charArray, fileInfo.size());

    file.close();



    set_header_dos();
    set_header_pe();
    set_header_pe_option();
    set_header_section();
    set_directory_export();
    set_directory_relocation();


}


//dos头
void MainWindow::set_header_dos(){

    /*
     * doc头格式：
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    DWORD e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
    */

    ui->textHeaderDoc->appendPlainText( "e_magic_pos: " + get_hex_Little_endian(dos_e_magic_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_cblp: " + get_hex_Little_endian(dos_e_cblp_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_cp: " + get_hex_Little_endian(dos_e_cp_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_crlc: " + get_hex_Little_endian(dos_e_crlc_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_cparhdr: " + get_hex_Little_endian(dos_e_cparhdr_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "_e_minalloc: " + get_hex_Little_endian(dos_e_minalloc_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_maxalloc: " + get_hex_Little_endian(dos_e_maxalloc_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_ss: " + get_hex_Little_endian(dos_e_ss_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_sp: " + get_hex_Little_endian(dos_e_sp_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_csum: " + get_hex_Little_endian(dos_e_csum_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_ip: " + get_hex_Little_endian(dos_e_ip_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_ip: " + get_hex_Little_endian(dos_e_cs_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_lfarlc: " + get_hex_Little_endian(dos_e_lfarlc_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_ovno: " + get_hex_Little_endian(dos_e_ovno_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_res: " + get_hex_Little_endian(dos_e_res_pos, dos_e_res_len) );
    ui->textHeaderDoc->appendPlainText( "e_oemid: " + get_hex_Little_endian(dos_e_oemid_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_oeminfo: " + get_hex_Little_endian(dos_e_oeminfo_pos, 2) );
    ui->textHeaderDoc->appendPlainText( "e_res2: " + get_hex_Little_endian(dos_e_res2_pos, dos_e_res2_len) );
    ui->textHeaderDoc->appendPlainText( "e_lfanew: " + get_hex_Little_endian(dos_e_lfanew_pos, dos_e_lfanew_len) );

    //获取pe位置
    QByteArray peArray = fileByteArray.mid(dos_e_lfanew_pos,dos_e_lfanew_len);
    std::reverse(peArray.begin(), peArray.end());
    bool ok;
    file_pos = peArray.toHex().toInt(&ok, 16);

}


//标准pe头
void MainWindow::set_header_pe(){

    /*
        typedef struct _IMAGE_FILE_HEADER
        {
            WORD Machine;
            WORD NumberOfSections;
            DWORD TimeDateStamp;
            DWORD PointerToSymbolTable;
            DWORD NumberOfSymbols;
            WORD SizeOfOptionalHeader;
            WORD Characteristics;
        } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    */

    ui->Machine->setText( get_hex_Little_endian(file_pos + pe_Machine_pos, 2) );
    ui->NumberOfSections->setText( get_hex_Little_endian(file_pos + pe_NumberOfSections_pos, 2) );
    ui->TimeDateStamp->setText( get_hex_Little_endian(file_pos + pe_TimeDateStamp_pos, 4) );
    ui->PointerToSymbolTable->setText( get_hex_Little_endian(file_pos + pe_PointerToSymbolTable_pos, 4) );
    ui->NumberOfSymbols->setText( get_hex_Little_endian(file_pos + pe_NumberOfSymbols_pos, 4) );
    ui->SizeOfOptionalHeader->setText( get_hex_Little_endian(file_pos + pe_SizeOfOptionalHeader_pos, 2) );
    ui->Characteristics->setText( get_hex_Little_endian(file_pos + pe_Characteristics_pos, 2) );

    //获取可选pe头大小
    QByteArray optionArray = fileByteArray.mid(file_pos + pe_SizeOfOptionalHeader_pos,2);
    std::reverse(optionArray.begin(), optionArray.end());
    bool ok;
    option_header_size = optionArray.toHex().toInt(&ok, 16);


    //计算区块表位置 = 标准PE头位置 + 标准PE头大小(24) + 可选PE头大小
    section_header_pos = file_pos + 24 +option_header_size;
    ui->textDesc->appendPlainText("区块位置：" + QString::number( section_header_pos) );


    //获取区块数量
    section_number = get_hex_Little_endian(file_pos + pe_NumberOfSections_pos, 2).toInt(&ok,16) ;
    ui->textDesc->appendPlainText("区块数量：" + QString::number( section_number) );


}

//可选pe头
void MainWindow::set_header_pe_option(){

    bool ok;
    QString image_base_string;
    if( "010B" == get_hex_Little_endian(file_pos + option_Magic_pos, 2)){
        // 32位结构
        ui->textOption->appendPlainText("32位 Option Header结构：");
        ui->textOption->appendPlainText(  "Magic: " + get_hex_Little_endian(file_pos + option_Magic_pos, 2) );
        ui->textOption->appendPlainText(  "MajorLinkerVersion: " + get_hex_Little_endian(file_pos + option_MajorLinkerVersion_pos, 1) );
        ui->textOption->appendPlainText(  "MinorLinkerVersion: " + get_hex_Little_endian(file_pos + option_MinorLinkerVersion_pos, 1) );
        ui->textOption->appendPlainText(  "SizeOfCode: " + get_hex_Little_endian(file_pos + option_SizeOfCode_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfInitializedData:" + get_hex_Little_endian(file_pos + option_SizeOfInitializedData_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfUninitializedData: " + get_hex_Little_endian(file_pos + option_SizeOfUninitializedData_pos, 4) );
        ui->textOption->appendPlainText(  "AddressOfEntryPoint: " + get_hex_Little_endian(file_pos + option_AddressOfEntryPoint_pos, 4) );
        ui->textOption->appendPlainText(  "BaseOfCode: " + get_hex_Little_endian(file_pos + option_BaseOfCode_pos, 4) );
        ui->textOption->appendPlainText(  "BaseOfData: " + get_hex_Little_endian(file_pos + option_BaseOfData_pos, 4) );
        ui->textOption->appendPlainText(  "ImageBase: " + get_hex_Little_endian(file_pos + option_ImageBase_pos, 4) );
        ui->textOption->appendPlainText(  "SectionAlignment: " + get_hex_Little_endian(file_pos + option_SectionAlignment_pos, 4) );
        ui->textOption->appendPlainText(  "FileAlignment: " + get_hex_Little_endian(file_pos + option_FileAlignment_pos, 4) );
        ui->textOption->appendPlainText(  "MajorOperatingSystemVersion: " + get_hex_Little_endian(file_pos + option_MajorOperatingSystemVersion_pos, 2) );
        ui->textOption->appendPlainText(  "MinorOperatingSystemVersion: " + get_hex_Little_endian(file_pos + option_MinorOperatingSystemVersion_pos, 2) );
        ui->textOption->appendPlainText(  "MajorImageVersion: " + get_hex_Little_endian(file_pos + option_MajorImageVersion_pos, 2) );
        ui->textOption->appendPlainText(  "MinorImageVersion: " + get_hex_Little_endian(file_pos + option_MinorImageVersion_pos, 2) );
        ui->textOption->appendPlainText(  "MajorSubsystemVersion: " + get_hex_Little_endian(file_pos + option_MajorSubsystemVersion_pos, 2) );
        ui->textOption->appendPlainText(  "MinorSubsystemVersion: " + get_hex_Little_endian(file_pos + option_MinorSubsystemVersion_pos, 2) );
        ui->textOption->appendPlainText(  "Win32VersionValue: " + get_hex_Little_endian(file_pos + option_Win32VersionValue_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfImage: " + get_hex_Little_endian(file_pos + option_SizeOfImage_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfHeaders: " + get_hex_Little_endian(file_pos + option_SizeOfHeaders_pos, 4) );
        ui->textOption->appendPlainText(  "CheckSum: " + get_hex_Little_endian(file_pos + option_CheckSum_pos, 4) );
        ui->textOption->appendPlainText(  "Subsystem: " + get_hex_Little_endian(file_pos + option_Subsystem_pos, 2) );
        ui->textOption->appendPlainText(  "DllCharacteristics: " + get_hex_Little_endian(file_pos + option_DllCharacteristics_pos, 2) );
        ui->textOption->appendPlainText(  "SizeOfStackReserve: " + get_hex_Little_endian(file_pos + option_SizeOfStackReserve_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfStackCommit: " + get_hex_Little_endian(file_pos + option_SizeOfStackCommit_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfHeapReserve: " + get_hex_Little_endian(file_pos + option_SizeOfHeapReserve_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfHeapCommit: " + get_hex_Little_endian(file_pos + option_SizeOfHeapCommit_pos, 4) );
        ui->textOption->appendPlainText(  "LoaderFlags: " + get_hex_Little_endian(file_pos + option_LoaderFlags_pos, 4) );
        ui->textOption->appendPlainText(  "NumberOfRvaAndSizes:" + get_hex_Little_endian(file_pos + option_NumberOfRvaAndSizes_pos, 4) );

        //内存镜像基址
        image_base = get_hex_Little_endian(file_pos + option_ImageBase_pos, 4).toInt(&ok,16) ;

    }else {

        // 64位结构
        ui->textOption->appendPlainText("64位 Option Header结构：");
        ui->textOption->appendPlainText(  "Magic: " + get_hex_Little_endian(file_pos + option_Magic64_pos, 2) );
        ui->textOption->appendPlainText(  "MajorLinkerVersion: " + get_hex_Little_endian(file_pos + option_MajorLinkerVersion64_pos, 1) );
        ui->textOption->appendPlainText(  "MinorLinkerVersion: " + get_hex_Little_endian(file_pos + option_MinorLinkerVersion64_pos, 1) );
        ui->textOption->appendPlainText(  "SizeOfCode: " + get_hex_Little_endian(file_pos + option_SizeOfCode64_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfInitializedData:" + get_hex_Little_endian(file_pos + option_SizeOfInitializedData64_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfUninitializedData: " + get_hex_Little_endian(file_pos + option_SizeOfUninitializedData64_pos, 4) );
        ui->textOption->appendPlainText(  "AddressOfEntryPoint: " + get_hex_Little_endian(file_pos + option_AddressOfEntryPoint64_pos, 4) );
        ui->textOption->appendPlainText(  "BaseOfCode: " + get_hex_Little_endian(file_pos + option_BaseOfCode64_pos, 4) );
        ui->textOption->appendPlainText(  "ImageBase: " + get_hex_Little_endian(file_pos + option_ImageBase64_pos, 8) );
        ui->textOption->appendPlainText(  "SectionAlignment: " + get_hex_Little_endian(file_pos + option_SectionAlignment64_pos, 4) );
        ui->textOption->appendPlainText(  "FileAlignment: " + get_hex_Little_endian(file_pos + option_FileAlignment64_pos, 4) );
        ui->textOption->appendPlainText(  "MajorOperatingSystemVersion: " + get_hex_Little_endian(file_pos + option_MajorOperatingSystemVersion64_pos, 2) );
        ui->textOption->appendPlainText(  "MinorOperatingSystemVersion: " + get_hex_Little_endian(file_pos + option_MinorOperatingSystemVersion64_pos, 2) );
        ui->textOption->appendPlainText(  "MajorImageVersion: " + get_hex_Little_endian(file_pos + option_MajorImageVersion64_pos, 2) );
        ui->textOption->appendPlainText(  "MinorImageVersion: " + get_hex_Little_endian(file_pos + option_MinorImageVersion64_pos, 2) );
        ui->textOption->appendPlainText(  "MajorSubsystemVersion: " + get_hex_Little_endian(file_pos + option_MajorSubsystemVersion64_pos, 2) );
        ui->textOption->appendPlainText(  "MinorSubsystemVersion: " + get_hex_Little_endian(file_pos + option_MinorSubsystemVersion64_pos, 2) );
        ui->textOption->appendPlainText(  "Win32VersionValue: " + get_hex_Little_endian(file_pos + option_Win32VersionValue64_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfImage: " + get_hex_Little_endian(file_pos + option_SizeOfImage64_pos, 4) );
        ui->textOption->appendPlainText(  "SizeOfHeaders: " + get_hex_Little_endian(file_pos + option_SizeOfHeaders64_pos, 4) );
        ui->textOption->appendPlainText(  "CheckSum: " + get_hex_Little_endian(file_pos + option_CheckSum64_pos, 4) );
        ui->textOption->appendPlainText(  "Subsystem: " + get_hex_Little_endian(file_pos + option_Subsystem64_pos, 2) );
        ui->textOption->appendPlainText(  "DllCharacteristics: " + get_hex_Little_endian(file_pos + option_DllCharacteristics64_pos, 2) );
        ui->textOption->appendPlainText(  "SizeOfStackReserve: " + get_hex_Little_endian(file_pos + option_SizeOfStackReserve64_pos, 8) );
        ui->textOption->appendPlainText(  "SizeOfStackCommit: " + get_hex_Little_endian(file_pos + option_SizeOfStackCommit64_pos, 8) );
        ui->textOption->appendPlainText(  "SizeOfHeapReserve: " + get_hex_Little_endian(file_pos + option_SizeOfHeapReserve64_pos, 8) );
        ui->textOption->appendPlainText(  "SizeOfHeapCommit: " + get_hex_Little_endian(file_pos + option_SizeOfHeapCommit64_pos, 8) );
        ui->textOption->appendPlainText(  "LoaderFlags: " + get_hex_Little_endian(file_pos + option_LoaderFlags64_pos, 4) );
        ui->textOption->appendPlainText(  "NumberOfRvaAndSizes:" + get_hex_Little_endian(file_pos + option_NumberOfRvaAndSizes64_pos, 4) );

        //内存镜像基址
        image_base = get_hex_Little_endian(file_pos + option_ImageBase64_pos, 4).toInt(&ok,16) ;

    }


    //保存 header大小
    size_of_headers = get_hex_Little_endian(file_pos + option_SizeOfHeaders_pos, 4).toInt(&ok,16) ;
    ui->textDesc->appendPlainText("文件头大小：" + QString::number( size_of_headers) );

    //内存中文件大小，未对齐之前大小
    size_of_image = get_hex_Little_endian(file_pos + option_SizeOfImage_pos, 4).toInt(&ok,16) ;

    //文件对齐大小
    file_alignment =  get_hex_Little_endian(file_pos + option_FileAlignment_pos, 4).toInt(&ok,16) ;
    ui->textDesc->appendPlainText("文件对齐大小：" + QString::number( file_alignment) );

    //内存对齐大小
    section_alignment = get_hex_Little_endian(file_pos + option_SectionAlignment_pos, 4).toInt(&ok,16) ;
    ui->textDesc->appendPlainText("内存对齐大小：" + QString::number( section_alignment) );

    //内存镜像基址
    ui->textDesc->appendPlainText("内存镜像基址：" + QString::number( image_base) );



}


//区块
void MainWindow::set_header_section(){

    //区块位置：select_header_pos
    //区块数量：pe头中 NumberOfSections
    //单个区块大小：40


    /*
        typedef struct _IMAGE_SECTION_HEADER {
            BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
            union {
                    DWORD   PhysicalAddress;
                    DWORD   VirtualSize;
            } Misc;
            DWORD   VirtualAddress;
            DWORD   SizeOfRawData;
            DWORD   PointerToRawData;
            DWORD   PointerToRelocations;
            DWORD   PointerToLinenumbers;
            WORD    NumberOfRelocations;
            WORD    NumberOfLinenumbers;
            DWORD   Characteristics;
        } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
    */

    qint8 section_size = 40;

    for(int i=0; i < section_number; i++){

        ui->textSection->appendPlainText(   QString("第 %1 个块：").arg(i+1));

        //获取区块name
        QByteArray tempArray = fileByteArray.mid(section_header_pos + i*section_size, 8);
        QString tempStr = QString(tempArray);


        ui->textSection->appendPlainText("IMAGE SIZEOF NAME: " + tempStr);
        ui->textSection->appendPlainText("Misc: " + get_hex_Little_endian(section_header_pos + i*section_size + 8, 4));
        ui->textSection->appendPlainText("VirtualAddress: " + get_hex_Little_endian(section_header_pos + i*section_size + 12, 4));
        ui->textSection->appendPlainText("SizeOfRawData: " + get_hex_Little_endian(section_header_pos + i*section_size + 16, 4));
        ui->textSection->appendPlainText("PointerToRawData: " + get_hex_Little_endian(section_header_pos + i*section_size + 20, 4));
        ui->textSection->appendPlainText("PointerToRelocations: " + get_hex_Little_endian(section_header_pos + i*section_size + 24, 4));
        ui->textSection->appendPlainText("PointerToLinenumbers: " + get_hex_Little_endian(section_header_pos + i*section_size + 28, 4));
        ui->textSection->appendPlainText("NumberOfRelocations: " + get_hex_Little_endian(section_header_pos + i*section_size + 32, 2));
        ui->textSection->appendPlainText("NumberOfLinenumbers: " + get_hex_Little_endian(section_header_pos + i*section_size + 34, 2));
        ui->textSection->appendPlainText("Characteristics: " + get_hex_Little_endian(section_header_pos + i*section_size + 36, 4));

        ui->textSection->appendPlainText( "" );
    }



}


//生成image buffer
void MainWindow::on_btnImageBuffer_clicked()
{

    /*
     * 1、确定image buffer大小。
     *      1.1 获取option头中 内存大小（SizeOfImage）
     *      1.2 SizeOfImage，根据SectionAlignment对齐。获取文件大小。
     * 2、拷贝doc头、file头、option file头、区块到 image buffer。拷贝 SizeOfHeader 大小。
     * 3、循环区块。放到image buffer中。
     *      3.1 获取区块数量（NumberOfSections的值）
     *      3.2 循环区块拷贝到 image buffer。因为快的大小是Misc，在文件中开始地址 PointerToRawData 拷贝misc字节，拷贝到 image buffer，开始地址是VirtualAddress
     */

    //获取内存中对齐之后大小
    qint32 image_size_total = (size_of_image / section_alignment + 1) *  section_alignment;

    QByteArray image_buffer = QByteArray(image_size_total, 0);

    //拷贝SizeOfHeader
    image_buffer.insert(0,fileByteArray.mid(0, size_of_headers));

    //拷贝区块
    qint8 section_size = 40;
    for(int i=0; i < section_number; i++){

        bool ok;
        int misc =  get_hex_Little_endian(section_header_pos + i*section_size + 8, 4).toInt(&ok, 16);
        qint32 virtual_address =  get_hex_Little_endian(section_header_pos + i*section_size + 12, 4).toInt(&ok, 16);
        qint32 pointer_to_raw_data = get_hex_Little_endian(section_header_pos + i*section_size + 20, 4).toInt(&ok, 16);

        image_buffer.insert(virtual_address, fileByteArray.mid(pointer_to_raw_data, misc));
    }


    //写入文件
    QFile writefile;
    QDataStream stream;
    QString storepath =  "/Users/zhangjx/Documents/workspace/qt-demo/image.bin";

    writefile.setFileName(storepath);
    writefile.open(QIODevice::WriteOnly);
    stream.setDevice(&writefile);
    stream.writeRawData(image_buffer, image_size_total);
    writefile.close();

    ui->textImageBuffer->appendPlainText(image_buffer.toHex());


    /*
     * 生成新的exe文件
     * 1、获取大小，计算文件对齐后大小
     * 2、拷贝 SizeOfHeader 大小 到 new_file_buffer
     * 3、循环拷贝区块到 new_file_buffer
     */
    int size = 2560;
    QByteArray new_file_array = QByteArray(size, 0);


    //拷贝 SizeOfHeader 大小 到 new_file_buffer
    new_file_array.insert(0, image_buffer.mid(0, size_of_headers));


    //循环拷贝区块到 new_file_buffer
    //拷贝区块
    for(int i=0; i < section_number; i++){

        bool ok;
        int misc =  get_hex_Little_endian(section_header_pos + i*section_size + 8, 4).toInt(&ok, 16);
        qint32 virtual_address =  get_hex_Little_endian(section_header_pos + i*section_size + 12, 4).toInt(&ok, 16);
        qint32 pointer_to_raw_data = get_hex_Little_endian(section_header_pos + i*section_size + 20, 4).toInt(&ok, 16);

        QByteArray temp_array = image_buffer.mid(virtual_address, misc);

        new_file_array.insert(pointer_to_raw_data , temp_array);
    }

    //写入文件
    QFile new_file;
    QDataStream new_stream;
    QString new_path =  "/Users/zhangjx/Documents/workspace/qt-demo/PENEW.exe";

    new_file.setFileName(new_path);
    new_file.open(QIODevice::WriteOnly);
    new_stream.setDevice(&new_file);
    new_stream.writeRawData(new_file_array, size);
    new_file.close();


}


//导出表
void MainWindow::set_directory_export(){

    /*
     *
     typedef struct _IMAGE_EXPORT_DIRECTORY
    {
        DWORD Characteristics; //属性 0x0
        DWORD TimeDateStamp; //时期邮戳 0x4
        WORD MajorVersion;  0x8
        WORD MinorVersion;  0xA
        DWORD Name;//模块名字 RVA   0xC
        DWORD Base;//基数，加上序书就是函数地址数组的索引值    0x10
        DWORD NumberOfFunctions;//函数个数  0x14    最大值-最小值+1，不一定准确
        DWORD NumberOfNames;//函数名字（有的有名字，有的没名字）0x18
        DWORD AddressOfFunctions;//RVA from base of image   0x1c
        DWORD AddressOfNames;//RVA from base of image   0x20
        DWORD AddressOfNameOrdinals;//RVA from base of image    0x24
    } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
     */


    bool ok;

    QString VirtualAddress;


    //默认32位
    qint32 start_pos = 0x78;
    if( "010B" == get_hex_Little_endian(file_pos + option_Magic_pos, 2)){
        // 32位结构
        ui->textExportTable->appendPlainText("********** 文件格式是32位 **********\n" );

    }else{
        // 64位结构
        ui->textExportTable->appendPlainText("********** 文件格式是64位 **********\n" );
        start_pos = 0x88;

    }


    VirtualAddress = get_hex_Little_endian(file_pos + start_pos, 0x4);
    ui->textExportTable->appendPlainText("导出表的地址 RVA：" + VirtualAddress );
    ui->textExportTable->appendPlainText("数据长度 size：" + get_hex_Little_endian(file_pos + start_pos + 0x4, 0x4));

    if( VirtualAddress.toInt(&ok, 16) == 0){
        return;
    }


    //打印三张表
    //rva转foa
    qint32 foa_value = rva_to_foa( VirtualAddress.toInt(&ok, 16));
    ui->textExportTable->appendPlainText("导出表偏移：" + QString::number(foa_value, 16) );


    //名字
    //QString name_addr_str = get_hex_Little_endian(foa_value + 0xC, 0x4);
    //ui->textExportTable->appendPlainText("名称：" + get_hex_Little_endian(file_pos + 0x84, 0x4));


    //基数
    qint32  base =  get_hex_Little_endian(foa_value + 0x10, 0x4).toInt(&ok, 16);
    ui->textExportTable->appendPlainText("基数：" + QString::number( base, 16) );

    //函数个数
    qint32  number_of_functions =  get_hex_Little_endian(foa_value + 0x14, 0x4).toInt(&ok, 16);
    ui->textExportTable->appendPlainText("函数个数" + QString::number(number_of_functions, 16) );




    //address Of function 导出函数地址表RVA
    QString address_of_function_string = get_hex_Little_endian(foa_value + 0x1c, 0x4);
    qint32 address_of_function = address_of_function_string.toInt(&ok, 16);
    qint32 foa_address_of_function = rva_to_foa(address_of_function);
    ui->textExportTable->appendPlainText("导出函数地址表：" + address_of_function_string);
    ui->textExportTable->appendPlainText("导出函数地址表 FOA：" + QString::number(foa_address_of_function,16));
    for(int i=0; i< number_of_functions; i++){
        ui->textExportTable->appendPlainText("导出函数地址：" +  get_hex_Little_endian(foa_address_of_function + i*4, 0x4) );
    }

    ui->textExportTable->appendPlainText("-------------"  );

    //address of name 导出函数名称表RVA
    QString address_of_name_string = get_hex_Little_endian(foa_value + 0x20, 0x4);
    qint32 address_of_name = address_of_name_string.toInt(&ok,16);
    qint32 foa_address_of_name = rva_to_foa(address_of_name);
    ui->textExportTable->appendPlainText("导出函数名称表：" + address_of_name_string);
    for(int i=0; i< number_of_functions; i++){
        ui->textExportTable->appendPlainText("导出函数名称 RVA：" +  get_hex_Little_endian(foa_address_of_name + i*4, 0x4) );

    }

    ui->textExportTable->appendPlainText("-------------"  );


    //address of name ordinal 导出函数序号表RVA
    QString address_of_name_ordinal_string = get_hex_Little_endian(foa_value + 0x24, 0x4);
    qint32 address_of_name_ordinal = address_of_name_ordinal_string.toInt(&ok,16);
    qint32 foa_address_of_name_ordinal = rva_to_foa(address_of_name_ordinal);
    ui->textExportTable->appendPlainText("导出函数序号表：" +  address_of_name_ordinal_string );
    for(int i=0; i< number_of_functions; i++){
        ui->textExportTable->appendPlainText("导出函数序号：" +  get_hex_Little_endian(foa_address_of_name_ordinal + i*2, 0x2) );
    }



}

//重定位表
void MainWindow::set_directory_relocation(){


    /*
    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD   VirtualAddress;
        DWORD   Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;


    typedef struct _IMAGE_BASE_RELOCATION {
        DWORD   VirtualAddress;
        DWORD   SizeOfBlock;
    } IMAGE_BASE_RELOCATION;
    typedef IMAGE_BASE_RELOCATION ，* PIMAGE_BASE_RELOCATION;

     */




    bool ok;

    QString VirtualAddress;
    qint32 foa_VirtualAddress;

    //默认32位
    qint32 start_pos = 0xA0;

    if( "010B" == get_hex_Little_endian(file_pos + option_Magic_pos, 2)){
        // 32位结构
        ui->textRelocation->appendPlainText("********** 文件格式是32位 **********\n" );

    }else{
        // 64位结构
        ui->textRelocation->appendPlainText("********** 文件格式是64位 **********\n" );
        start_pos = 0xB0;

    }

    VirtualAddress = get_hex_Little_endian(file_pos + start_pos, 0x4);
    foa_VirtualAddress = rva_to_foa( VirtualAddress.toInt(&ok,16));
    ui->textRelocation->appendPlainText("重定位表 RVA：" + VirtualAddress );
    ui->textRelocation->appendPlainText("重定位表 FOA：" + QString::number(foa_VirtualAddress, 16) );
    ui->textRelocation->appendPlainText("重定位表 size：" + get_hex_Little_endian(file_pos + start_pos, 0x4));


    qint32 i = 0;
    qint32 block_pos = 0;
    // 解析重定位快
    QString BASE_RELOCATION = "1";
    QString SizeOfBlock = "1";


    block_pos = foa_VirtualAddress;
    while ( BASE_RELOCATION != "00000000" ) {

        BASE_RELOCATION = get_hex_Little_endian(block_pos, 0x4);

        //不打印结束标识
        if( BASE_RELOCATION == "00000000" ){
            return;
        }

        ui->textRelocation->appendPlainText("---------------------" );
        ui->textRelocation->appendPlainText("第" + QString::number(i+1, 16) +"个Block地址：" + BASE_RELOCATION );
        SizeOfBlock = get_hex_Little_endian(block_pos + 0x4, 0x4);
        ui->textRelocation->appendPlainText("第" + QString::number(i+1, 16) +"个Block大小：" + SizeOfBlock );

        //计算数量  = ( [SizeOfBlock] - VirtualAddress宽度 - SizeOfBlock宽度 ) / 2
        qint32 block_number = (SizeOfBlock.toInt(&ok, 16) - 0x8 )/2;
        ui->textRelocation->appendPlainText("数量：" + QString::number(block_number,16) );

        for(int j=0;j<block_number;j++){
            QString value = get_hex_Little_endian(block_pos + 0x8 + 2*j, 0x2);
            ui->textRelocation->appendPlainText(value);

        }

        block_pos = block_pos + SizeOfBlock.toInt(&ok, 16);
        i++;

    }

}



qint32 MainWindow::foa_to_rva(qint32 foa_value){

    /*
     * 1、循环块区，当 PointerToRawData + Misc < 地址 < PointerToRawData  + Misc，获取区块序号。获取该区块的 PointerToRawData
     * 2、VirtualAddress + misc 等于 rva
     */

    qint8 section_size = 40;
    bool ok;

    for(int i=0; i < section_number; i++){

        //Misc
        QByteArray Misc_array =  fileByteArray.mid(section_header_pos + i*section_size + 8, 4);
        std::reverse(Misc_array.begin(), Misc_array.end());
        qint32 misc = Misc_array.toHex().toInt(&ok, 16);

        //PointerToRawData
        QByteArray PointerToRawData_array =  fileByteArray.mid(section_header_pos + i*section_size + 20, 4);
        std::reverse(PointerToRawData_array.begin(), PointerToRawData_array.end());
        qint32 PointerToRawData = PointerToRawData_array.toHex().toInt(&ok, 16);

        if( foa_value >=  PointerToRawData && foa_value <=  (PointerToRawData + misc)) {
            //获取值
            //VirtualAddress
            QByteArray VirtualAddress_array =  fileByteArray.mid(section_header_pos + i*section_size + 12, 4);
            std::reverse(VirtualAddress_array.begin(), VirtualAddress_array.end());

            qint32 addr = VirtualAddress_array.toHex().toInt(&ok, 16) + (foa_value-PointerToRawData);
//            return  QString::number(addr, 16);
            return addr;
        }

    }

    return 0;


}

qint32 MainWindow::rva_to_foa(qint32 rva_value){


    /*
     * 1、循环块区，当 VirtualAddress + Misc < 地址 < VirtualAddress + Misc，获取区块序号。获取该区块的 PointerToRawData
     * 2、PointerToRawData + misc 等于 foa
     */

    qint8 section_size = 40;
    bool ok;

    for(int i=0; i < section_number; i++){

        //Misc
        QByteArray Misc_array =  fileByteArray.mid(section_header_pos + i*section_size + 8, 4);
        std::reverse(Misc_array.begin(), Misc_array.end());
        qint32 misc = Misc_array.toHex().toInt(&ok, 16);


        //VirtualAddress
        QByteArray VirtualAddress_array =  fileByteArray.mid(section_header_pos + i*section_size + 12, 4);
        std::reverse(VirtualAddress_array.begin(), VirtualAddress_array.end());
        qint32 VirtualAddress = VirtualAddress_array.toHex().toInt(&ok, 16);


        if( rva_value >=  VirtualAddress && rva_value <=  (VirtualAddress + misc)){

            //PointerToRawData
            QByteArray PointerToRawData_array =  fileByteArray.mid(section_header_pos + i*section_size + 20, 4);
            std::reverse(PointerToRawData_array.begin(), PointerToRawData_array.end());

            qint32 addr = PointerToRawData_array.toHex().toInt(&ok, 16) + (rva_value-VirtualAddress);
//            return  QString::number(addr, 16);
            return addr;
        }

    }

    return 0;

}

/*
 * 获取16进制小端字符串
 *
 * pos：开始位置
 * len：长度
 */
QString MainWindow::get_hex_Little_endian(qint32 pos, qint32 len){

    QByteArray tempArray = fileByteArray.mid(pos,len);

    std::reverse(tempArray.begin(), tempArray.end());

    return tempArray.toHex().toUpper();

}



void MainWindow::on_btnFoa2Rva_clicked()
{

    QString foa = ui->textFOA->text().trimmed();
    bool ok;

    qint32 foa_value = foa.toInt(&ok, 16);

    ui->textRVA->setText( QString::number(foa_to_rva(foa_value),16 )) ;

}

void MainWindow::on_btnRva2Foa_clicked()
{
    QString rva = ui->textRVA->text().trimmed();
    bool ok;

    qint32 rva_value = rva.toInt(&ok, 16);

    ui->textFOA->setText( QString::number(rva_to_foa(rva_value), 16) ) ;

}
