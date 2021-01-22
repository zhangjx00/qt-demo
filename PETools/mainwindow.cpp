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
    QString pathName = "/Users/zhangjx/Documents/workspace/qt-demo/PE.exe";
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

    set_header_dos();
    set_header_pe();
    set_header_pe_option();
    set_header_section();

    on_btnImageBuffer_clicked();

    file.close();

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


    }


    //保存 header大小
    bool ok;
    size_of_headers = get_hex_Little_endian(file_pos + option_SizeOfHeaders_pos, 4).toInt(&ok,16) ;
    ui->textDesc->appendPlainText("文件头大小：" + QString::number( size_of_headers) );

    //内存中文件大小，未对齐之前大小
    size_of_image = get_hex_Little_endian(file_pos + option_SizeOfImage_pos, 4).toInt(&ok,16) ;

    //文件对齐大小
    file_alignment =  get_hex_Little_endian(file_pos + option_FileAlignment_pos, 4).toInt(&ok,16) ;
    ui->textDesc->appendPlainText("文件对齐大小：" + QString::number( file_alignment) );

    //内存对齐大小
    section_alignment = get_hex_Little_endian(file_pos + option_SectionAlignment_pos, 4).toInt(&ok,16) ;
    ui->textDesc->appendPlainText("内存对齐大小" + QString::number( section_alignment) );


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
    QString storepath =  "da.bin";

    writefile.setFileName(storepath);
    writefile.open(QIODevice::WriteOnly);
    stream.setDevice(&writefile);
    stream.writeRawData(image_buffer, image_size_total);
    writefile.close();

    ui->textImageBuffer->appendPlainText(image_buffer.toHex());

}

//生成新的exe文件
void MainWindow::on_btnNewFile_clicked()
{

}
