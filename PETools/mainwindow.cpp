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
    QString pathName = QFileDialog::getOpenFileName(this,tr("打开一个文件"),QDir::currentPath(),"PE文件(*.exe)");
    QFile file(pathName);
    if(!file.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(this,"错误","打开失败！！",QMessageBox::Ok,QMessageBox::Ok);
        return;
    }


    //用文本流读取文件
    QDataStream aStream(&file);

    //windows平台
    aStream.setByteOrder(QDataStream::LittleEndian);

    set_header_dos(&aStream);

    file.close();

}

void MainWindow::set_header_dos(QDataStream* dataStream){

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

    ui->e_magic->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_cblp->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_cp->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_crlc->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_cparhdr->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_minalloc->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_maxalloc->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_ss->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_sp->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_csum->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_ip->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_cs->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_lfarlc->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_ovno->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_res->setText( get_hex_data_stream(dataStream, 8) );
    ui->e_oemid->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_oeminfo->setText( get_hex_data_stream(dataStream, 2) );
    ui->e_res2->setText( get_hex_data_stream(dataStream, 20) );
    ui->e_lfanew->setText( get_hex_data_stream(dataStream, 4) );
}



//获取文件数据，小端
QString MainWindow::get_hex_data_stream(QDataStream* dataStream, quint8 byteSize){

    char* charArray = new  char[byteSize]{0};
    dataStream->readRawData(charArray, byteSize);


    QString dataString;
    for(int i = byteSize -1 ;i >= 0; i--){
        qint8 outChar = *(charArray + i);
        QString str = QString("%1").arg(outChar&0xFF,2,16,QLatin1Char('0')).toUpper() ;
        dataString += str;
    }
    return dataString;

}



