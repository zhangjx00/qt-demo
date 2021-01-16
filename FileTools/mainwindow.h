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
    QStringList filePathlist;
    void get_filelist(const QString &path);

private slots:
    void on_btnSelectPath_clicked();

    void on_btnDele_clicked();

    void on_btnAdd_clicked();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
