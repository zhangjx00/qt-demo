#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //初始化树
}

MainWindow::~MainWindow()
{
    delete ui;
}



void MainWindow:: get_filelist(const QString &path)
{

    QDir dir(path);
    QFileInfoList list = dir.entryInfoList(QDir::AllEntries|QDir::NoDotAndDotDot);

    foreach(QFileInfo fileInfo,list )
    {
        filePathlist.append(fileInfo.absoluteFilePath());
        ui->plainTextEdit->appendPlainText(fileInfo.absoluteFilePath());

        if(fileInfo.isDir()){
            get_filelist(fileInfo.absoluteFilePath());
        }
    }

}



void MainWindow::on_btnSelectPath_clicked()
{
    QString curDir=QDir::currentPath();
    QString aDir=QFileDialog::getExistingDirectory(this,"选择一个目录",curDir,QFileDialog::ShowDirsOnly);
    ui->textSelectPath->setText(aDir);

    if(aDir == ""){
        return;
    }

    //清空filePathlist 和 plainTextEdit
    filePathlist.clear();
    ui->plainTextEdit->clear();

    get_filelist(aDir);
}

//遍历 filePathlist ，如果文件名字中包含lineEdit中文字，删掉
void MainWindow::on_btnDele_clicked()
{
    QString delContent = ui->lineEdit->text();

    for ( int i = filePathlist.size(); i > 0; i--) {

        QFileInfo  fileInfo(filePathlist[i-1]);
        QFile file(filePathlist[i-1]);

        //文件不存在
        if (!file.exists()) { continue;}

        //判断文件名字中是否包含
        QString fileName = fileInfo.fileName();
        if(!fileName.contains(delContent)){
            continue;
        }

        fileName.remove(delContent);

        QString newPath = fileInfo.absolutePath() + QDir::separator() + fileName ;

        //修改文件名字
        file.rename(newPath);

    }


    QMessageBox::about(NULL, "About", "操作成功");

    //刷新显示
    filePathlist.clear();
    ui->plainTextEdit->clear();
    get_filelist( ui->textSelectPath->text() );

}

//遍历filePathlist，文件名增加 lineEdit中文字
void MainWindow::on_btnAdd_clicked()
{

    QString addContent = ui->lineEdit->text();

    for ( int i = filePathlist.size(); i > 0; i--) {

        QFileInfo  fileInfo(filePathlist[i-1]);
        QFile file(filePathlist[i-1]);

        //文件不存在
        if (!file.exists()) { continue;}

        QString newFileName = fileInfo.completeBaseName() + addContent;
        QString newPath = fileInfo.absolutePath() + QDir::separator() +newFileName ;

        if(fileInfo.isFile()){

            newPath = newPath + + "." + fileInfo.completeSuffix();
        }


        file.rename(newPath);

    }

    QMessageBox::about(NULL, "About", "操作成功");

    //刷新显示
    filePathlist.clear();
    ui->plainTextEdit->clear();
    get_filelist( ui->textSelectPath->text() );


}

