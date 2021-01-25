#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include    <QFileDialog>
#include    <QDateTime>
#include    <QTemporaryDir>
#include    <QTemporaryFile>
#include    <QDebug>
#include    <QListWidgetItem>
#include    <QDirIterator>
#include    <QMessageBox>
#include    <QTextCodec>
#include    <QDebug>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();


public:
    void set_header_dos();
    void set_header_pe();
    void set_header_pe_option();
    void set_header_section();
    void set_directory_export();

    QString get_hex_Little_endian(qint32 pos, qint32 len);


    QString foa_to_rva(qint32 foa_value);
    QString rva_to_foa(qint32 rva_value);


    //存储pe文件
    QByteArray fileByteArray;


private slots:
    void on_btnSelectFile_clicked();
    void on_btnImageBuffer_clicked();


    void on_btnFoa2Rva_clicked();

    void on_btnRva2Foa_clicked();

private:
    Ui::MainWindow *ui;

public:

    /*
        dos头
    */
    //位置信息
    qint32 dos_e_magic_pos = 0;
    qint32 dos_e_cblp_pos = 2;
    qint32 dos_e_cp_pos = 4;
    qint32 dos_e_crlc_pos = 6;
    qint32 dos_e_cparhdr_pos = 8;
    qint32 dos_e_minalloc_pos = 10;
    qint32 dos_e_maxalloc_pos = 12;
    qint32 dos_e_ss_pos = 14;
    qint32 dos_e_sp_pos = 16;
    qint32 dos_e_csum_pos = 18;
    qint32 dos_e_ip_pos = 20;
    qint32 dos_e_cs_pos = 22;
    qint32 dos_e_lfarlc_pos = 24;
    qint32 dos_e_ovno_pos = 26;
    qint32 dos_e_res_pos = 34;
    qint32 dos_e_oemid_pos = 36;
    qint32 dos_e_oeminfo_pos = 38;
    qint32 dos_e_res2_pos = 40;
    qint32 dos_e_lfanew_pos = 60;

    //长度，除了dos_e_res_len、dos_e_res2_len、dos_e_lfanew_len。其他都是2字节
    qint32 dos_e_res_len = 8;
    qint32 dos_e_res2_len = 20;
    qint32 dos_e_lfanew_len = 4;


    /*
     * pe文件头
     */
    int file_pos;
    qint32 file_pos_len = 4;

    qint32 pe_Machine_pos = 4;
    qint32 pe_NumberOfSections_pos = 6;
    qint32 pe_TimeDateStamp_pos = 8;
    qint32 pe_PointerToSymbolTable_pos = 12;
    qint32 pe_NumberOfSymbols_pos = 16;
    qint32 pe_SizeOfOptionalHeader_pos = 20;
    qint32 pe_Characteristics_pos = 22;


    /*
     * 32位可选pe文件头
     *
     */
    qint32 option_Magic_pos = 24;
    qint32 option_MajorLinkerVersion_pos = 26;
    qint32 option_MinorLinkerVersion_pos = 27;
    qint32 option_SizeOfCode_pos = 28;
    qint32 option_SizeOfInitializedData_pos = 32;
    qint32 option_SizeOfUninitializedData_pos = 36;
    qint32 option_AddressOfEntryPoint_pos = 40;
    qint32 option_BaseOfCode_pos = 44;
    qint32 option_BaseOfData_pos = 48;
    qint32 option_ImageBase_pos = 52;
    qint32 option_SectionAlignment_pos = 56;
    qint32 option_FileAlignment_pos = 60;
    qint32 option_MajorOperatingSystemVersion_pos = 64;
    qint32 option_MinorOperatingSystemVersion_pos = 66;
    qint32 option_MajorImageVersion_pos = 68;
    qint32 option_MinorImageVersion_pos = 70;
    qint32 option_MajorSubsystemVersion_pos = 72;
    qint32 option_MinorSubsystemVersion_pos = 74;
    qint32 option_Win32VersionValue_pos = 76;
    qint32 option_SizeOfImage_pos = 80;
    qint32 option_SizeOfHeaders_pos = 84;
    qint32 option_CheckSum_pos = 88;
    qint32 option_Subsystem_pos = 92;
    qint32 option_DllCharacteristics_pos = 94;
    qint32 option_SizeOfStackReserve_pos = 96;
    qint32 option_SizeOfStackCommit_pos = 100;
    qint32 option_SizeOfHeapReserve_pos = 104;
    qint32 option_SizeOfHeapCommit_pos = 108;
    qint32 option_LoaderFlags_pos = 112;
    qint32 option_NumberOfRvaAndSizes_pos = 116;

    /*
     * 64位可选pe文件头
     */
    qint32 option_Magic64_pos = 24;
    qint32 option_MajorLinkerVersion64_pos = 26;
    qint32 option_MinorLinkerVersion64_pos = 27;
    qint32 option_SizeOfCode64_pos = 28;
    qint32 option_SizeOfInitializedData64_pos = 32;
    qint32 option_SizeOfUninitializedData64_pos = 36;
    qint32 option_AddressOfEntryPoint64_pos = 40;
    qint32 option_BaseOfCode64_pos = 44;
    //qint32 option_BaseOfData64;
    qint32 option_ImageBase64_pos = 48;
    qint32 option_SectionAlignment64_pos = 56;
    qint32 option_FileAlignment64_pos = 60;
    qint32 option_MajorOperatingSystemVersion64_pos = 64;
    qint32 option_MinorOperatingSystemVersion64_pos = 66;
    qint32 option_MajorImageVersion64_pos = 68;
    qint32 option_MinorImageVersion64_pos = 70;
    qint32 option_MajorSubsystemVersion64_pos = 72;
    qint32 option_MinorSubsystemVersion64_pos = 74;
    qint32 option_Win32VersionValue64_pos = 76;
    qint32 option_SizeOfImage64_pos = 80;
    qint32 option_SizeOfHeaders64_pos = 84;
    qint32 option_CheckSum64_pos = 88;
    qint32 option_Subsystem64_pos = 92;
    qint32 option_DllCharacteristics64_pos = 94;
    qint32 option_SizeOfStackReserve64_pos = 96;
    qint32 option_SizeOfStackCommit64_pos = 104;
    qint32 option_SizeOfHeapReserve64_pos = 112;
    qint32 option_SizeOfHeapCommit64_pos = 120;
    qint32 option_LoaderFlags64_pos = 128;
    qint32 option_NumberOfRvaAndSizes64_pos = 132;


    //可选pe头大小
    qint32 option_header_size;


    //pe文件再内存中大小，未对其之前的大小
    qint32 size_of_image;

    //内存镜像基址
    qint32 image_base;


    //快表位置
    qint32 section_header_pos;
    //区块数量
    qint32 section_number;


    //header大小
    qint32 size_of_headers;

    //内存对齐大小
    qint32 section_alignment;

    //文件对齐大小
    qint32 file_alignment;


};
#endif // MAINWINDOW_H
