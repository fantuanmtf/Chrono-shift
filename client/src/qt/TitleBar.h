#ifndef TITLEBAR_H
#define TITLEBAR_H

#include <QWidget>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QMouseEvent>

class TitleBar : public QWidget
{
    Q_OBJECT

public:
    explicit TitleBar(QWidget *parent = nullptr);
    ~TitleBar();

    void setMoveTarget(QWidget* target);

signals:
    void minimizeClicked();
    void maximizeClicked();
    void closeClicked();

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;

private:
    void setupUi();

    QLabel* m_titleLabel;
    QPushButton* m_minimizeBtn;
    QPushButton* m_maximizeBtn;
    QPushButton* m_closeBtn;

    QWidget* m_moveTarget;
};

#endif // TITLEBAR_H