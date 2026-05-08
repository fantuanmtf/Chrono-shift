#ifndef SETTINGSWIDGET_H
#define SETTINGSWIDGET_H

#include <QWidget>
#include <QPushButton>
#include <QCheckBox>
#include <QLineEdit>
#include <QSlider>
#include <QLabel>

class SettingsWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SettingsWidget(QWidget *parent = nullptr);
    ~SettingsWidget();

signals:
    void backClicked();
    void themeChanged(bool dark);

private slots:
    void onBackClicked();
    void onThemeToggle(bool checked);
    void onSaveClicked();

private:
    void setupUi();

    QPushButton* m_backBtn;
    QPushButton* m_saveBtn;
    QCheckBox* m_darkThemeCheck;
    QCheckBox* m_notificationsCheck;
    QCheckBox* m_autoConnectCheck;
    QLineEdit* m_hostEdit;
    QLineEdit* m_portEdit;
    QSlider* m_fontSizeSlider;
    QLabel* m_fontSizeLabel;
};

#endif // SETTINGSWIDGET_H