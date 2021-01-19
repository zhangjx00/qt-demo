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
    void set_header_dos(QDataStream* dataStream);
    QString get_hex_data_stream(QDataStream* dataStream, quint8 byteSize);

private slots:
    void on_btnSelectFile_clicked();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
