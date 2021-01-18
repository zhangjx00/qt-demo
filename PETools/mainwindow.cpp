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

//char数组转字符串
QString MainWindow::toHexStr(QByteArray data, int len = 0)
{
    QString tempStr= "";
    peHexStr = data.toHex();//把QByteArray转为Hex编码


//    len = (len == 0)? peHexStr.length() : len;//不带len参数调用时,通过length()方法获取长度
//    for (int i=0; i<len; i=i+2) {
//        tempStr += peHexStr.mid(i, 2) + " ";//加空格
//    }
//    //trimmed():删除字符串开头和末尾的空格
//    //toUpper():将字符串转换成大写
//    return tempStr.trimmed().toUpper();

    return peHexStr;

}

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

    //获取文件大小
    QFileInfo fileInfo(pathName);
    char datRawArray[fileInfo.size()];

    //读取文件到 data 中
    QDataStream data(&file);
    data.readRawData(datRawArray,fileInfo.size());

    //转字符串
    QString hexStr = toHexStr(QByteArray((const char*)datRawArray, fileInfo.size()));



//    ui->textPEAll->appendPlainText(hexStr);


    set_header_dos();

    file.close();

}

void MainWindow::set_header_dos(){


    ui->e_magic->setText(peHexStr.mid(0,4));
    ui->e_cblp->setText(peHexStr.mid(0,4));
    ui->e_cp->setText(peHexStr.mid(0,4));
    ui->e_crlc->setText(peHexStr.mid(0,4));
    ui->e_cparhdr->setText(peHexStr.mid(0,4));
    ui->e_minalloc->setText(peHexStr.mid(0,4));
    ui->e_maxalloc->setText(peHexStr.mid(0,4));
    ui->e_ss->setText(peHexStr.mid(0,4));
    ui->e_sp->setText(peHexStr.mid(0,4));
    ui->e_csum->setText(peHexStr.mid(0,4));
    ui->e_ip->setText(peHexStr.mid(0,4));
    ui->e_cs->setText(peHexStr.mid(0,4));
    ui->e_lfarlc->setText(peHexStr.mid(0,4));
    ui->e_ovno->setText(peHexStr.mid(0,4));
    ui->e_res->setText(peHexStr.mid(0,4));
    ui->e_oemid->setText(peHexStr.mid(0,4));
    ui->e_oeminfo->setText(peHexStr.mid(0,4));
    ui->e_res2->setText(peHexStr.mid(0,4));
    ui->e_lfanew->setText(peHexStr.mid(0,4));


}
