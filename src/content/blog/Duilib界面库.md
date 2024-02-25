---
author: s0rry
pubDatetime: 2022-11-28T00:20:00Z
modDatetime: 2022-11-28T08:12:00Z
title: Duilib界面库
slug: Duilib
featured: false
draft: false
tags:
  - windows
description: DuiLib是一款界面开发库
---

## 介绍

暑假时候，学习免杀做界面的时候学的知识，整理一下贴出来。

DuiLib是一款强大的界面开发库，将用户界面和逻辑处理进行分离。其使用XML描述界面风格和布局，可以很方便的构建高效、绚丽的、非常易于扩展的界面。

## 环境配置

我先照着这个链接配置结果挺多报错的，这个用的是网易改版后的duilib库（https://www.cnblogs.com/pandamohist/p/14110980.html），最后换成了原版的duilib库用的是真丝滑。

这里我采用vcpkg来安装原版的duilib库。vcpkg(https://github.com/microsoft/vcpkg)是Microsoft的跨平台开源软件包管理器，配合vs的vcpkp很舒服。下载下来，编译成功，添加到环境变量。运行下面命令：

```
vcpkg install duilib
```

将vcpkg下载的库在vs中调用则直接参考链接中的内容(https://www.jianshu.com/p/a1662ad8814d) 这里就不赘述了。

## duilib中的颜色描述

采用32位色，相比24位的RGB颜色多了一字节来描述透明度。

windows下的32位是R、G、B三个通道各占8位共24位，加上明度通道8位，所以是32位，24位也就是R、G、B三个通道各占6位共18位，加上明度通道6位，所以是24位。

32位颜色值一般这样分配：X8位，R8位，G8位，B8位或A8位，R8位，G8位，B8位。也就是说第一字节是用来描述透明度的

## helloword之duilib

下面这段代码可以能体现duilib的基本使用方法

```
class CDuiFrameWnd : public CWindowWnd, public INotifyUI
{
public:
    virtual LPCTSTR GetWindowClassName() const { return _T("DUIMainFrame"); }  // c设置窗口名字
    virtual void    Notify(TNotifyUI& msg) {} // 设置消息处理

    virtual LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)
    {
        LRESULT lRes = 0;

        if (uMsg == WM_CREATE)
        {
            CControlUI* pWnd = new CButtonUI;
            pWnd->SetText(_T("Hello World"));   // 设置文字
            pWnd->SetBkColor(0xFFFFFFFF);       // 设置背景色

            m_PaintManager.Init(m_hWnd);
            m_PaintManager.AttachDialog(pWnd;
            return lRes;
        }

        if (m_PaintManager.MessageHandler(uMsg, wParam, lParam, lRes))
        {
            return lRes;
        }

        return __super::HandleMessage(uMsg, wParam, lParam);
    }

protected:
    CPaintManagerUI m_PaintManager; // 这个很重要用于获取窗口中的控件对象
};

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
    CPaintManagerUI::SetInstance(hInstance); // 设置路径
    CPaintManagerUI::SetResourcePath(CPaintManagerUI::GetInstancePath());   // 设置资源的默认路径（此处设置为和exe在同一目录）

    CDuiFrameWnd duiFrame;
    duiFrame.Create(NULL, _T("DUIWnd"), UI_WNDSTYLE_FRAME, WS_EX_WINDOWEDGE);
    duiFrame.CenterWindow();
    duiFrame.ShowModal();
    return 0;
}
```

## duilib进阶之消息处理

才用xml来加载界面，比直接写代码快太多了，整体思路与上面的helloword一样，通过对父类CWindowWnd的重写，就可以控制一个窗口创建的过程。

CMainWnd::OnCreate： 在窗口创建的时候要执行的操作，这里就是会加载我放进程序里的xml文件。

CMainWnd::OnNcHitTest：鼠标点击的时候要执行的操作，可以通过这个更改点击特效

CMainWnd::OnSysCommand：系统发送来的消息的处理

CMainWnd::HandleMessage：窗口的主要控制函数，分发窗口的消息

CMainWnd::Notify：单独封装出来的消息处理函数，用来处理控件的相关事件

```
using namespace DuiLib;
class CMainWnd : public CWindowWnd, public INotifyUI, public IDialogBuilderCallback
{
public:
	CMainWnd();
	~CMainWnd();

	LPCTSTR GetWindowClassName() const { return _T("CMainWnd"); }
	UINT GetClassStyle() const { return CS_DBLCLKS; };
	void OnFinalMessage(HWND ) {  };
	void Notify(TNotifyUI& msg);

	CControlUI* CreateControl(LPCTSTR pstrClass);

public:
	LRESULT OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	LRESULT OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	LRESULT OnSysCommand(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);

public:
	void InitDlg();

public:
	CPaintManagerUI m_PM;
};
```

```
CMainWnd::CMainWnd()
{
}

CMainWnd::~CMainWnd()
{
}

CControlUI* CMainWnd::CreateControl(LPCTSTR pstrClass)
{
	return NULL;
}

LRESULT CMainWnd::OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	LONG styleValue = ::GetWindowLong(*this, GWL_STYLE);
	styleValue &= ~WS_CAPTION;
	styleValue &= ~WS_SIZEBOX;
	::SetWindowLong(*this, GWL_STYLE, styleValue | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);

	m_PM.Init(m_hWnd);
	CDialogBuilder builder;
	CControlUI* pRoot = builder.Create(IDR_XML1, _T("xml"), this, &m_PM);
	ASSERT(pRoot && "Failed to parse XML");
	m_PM.AttachDialog(pRoot);
	m_PM.AddNotifier(this);

	return 0;
}

void CMainWnd::InitDlg()
{
}

LRESULT CMainWnd::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LRESULT lRes = 0;
	BOOL bHandled = TRUE;

	switch (uMsg)
	{
	case WM_CREATE:				lRes = OnCreate(uMsg, wParam, lParam, bHandled);		break;
	case WM_NCHITTEST:			lRes = OnNcHitTest(uMsg, wParam, lParam, bHandled);		break;
	case WM_SYSCOMMAND:			lRes = OnSysCommand(uMsg, wParam, lParam, bHandled);	break;
	case WM_KEYDOWN:
	{
		if (wParam == VK_ESCAPE)
		{
			Close();
		}
		else
			bHandled = FALSE;
	}
	default:
		bHandled = FALSE;
	}
	if (bHandled) return lRes;
	if (m_PM.MessageHandler(uMsg, wParam, lParam, lRes)) return lRes;
	return CWindowWnd::HandleMessage(uMsg, wParam, lParam);
}

void CMainWnd::Notify(TNotifyUI& msg)
{
	if (msg.sType == DUI_MSGTYPE_WINDOWINIT)
	{
		InitDlg();
	}
    LPTSTR click_ = (LPTSTR)msg.sType.GetData();
    LPTSTR click = encrypStringW(click_);
    if (!MyTStrcmp(click, (LPTSTR)ENclick,5))
    {

        // 注意把enter1的字符串加密了
        CDuiString sCtrlName = msg.pSender->GetName();
        LPTSTR controlName_ = (LPTSTR)sCtrlName.GetData();
        LPTSTR controlName = (LPTSTR)encrypStringW(controlName_);
        if (!MyTStrcmp(controlName, (LPTSTR)ENsign, 4))
        {
            LPCTSTR account = NULL;
            LPCTSTR password = NULL;
            auto editFilePath = (CEditUI*)m_PM.FindControl(_T("account"));
            account = editFilePath->GetText().GetData();
            editFilePath = (CEditUI*)m_PM.FindControl(_T("password"));
            password = editFilePath->GetText().GetData();
            WCHAR* out = (WCHAR*)malloc(100);
            // ::MessageBoxW(NULL, password, L"提示", 0);
            switch (CheckMain(account, password))
            {
            case 1:
                // succcess
                ::MessageBox(NULL, out, L"成功登录", 0);
                free(out);
                break;
            case 0:
                // worse
                ::MessageBox(NULL, L"账号或者密码不对", L"提示", 0);
                break;
            case -1:
                // length woring
                ::MessageBox(NULL, L"账号或者密码的长度不对", L"提示", 0);
                break;
            case -2:
                // string == NULL
                ::MessageBox(NULL, L"账号或密码不能为空", L"注意", 0);
                break;
            default:
                // error
                break;
            }

            return;
        }

        else if (!MyTStrcmp(controlName, (LPTSTR)ENidea, 4)) {
        }

        else if (!MyTStrcmp(controlName, (LPTSTR)ENclosebtn, 8)) {
            Close();
            return;
        }
        else if (!MyTStrcmp(controlName, (LPTSTR)ENminbtn, 6))
        {
            SendMessage(WM_SYSCOMMAND, SC_MINIMIZE, 0);
            return;
        }
        else if (!MyTStrcmp(controlName, (LPTSTR)ENmaxbtn, 6))
        {
            SendMessage(WM_SYSCOMMAND, SC_MAXIMIZE, 0);
            return;
        }
        else if (!MyTStrcmp(controlName, (LPTSTR)ENrestorebtn, 10))
        {
            SendMessage(WM_SYSCOMMAND, SC_RESTORE, 0);
            return;
        }
        return;
    }
}

LRESULT CMainWnd::OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	POINT pt; pt.x = GET_X_LPARAM(lParam); pt.y = GET_Y_LPARAM(lParam);
	::ScreenToClient(*this, &pt);

	RECT rcClient;
	::GetClientRect(*this, &rcClient);

	RECT rcCaption = m_PM.GetCaptionRect();
	if (pt.x >= rcClient.left + rcCaption.left && pt.x < rcClient.right - rcCaption.right \
		&& pt.y >= rcCaption.top && pt.y < rcCaption.bottom) {
		CControlUI* pControl = static_cast<CControlUI*>(m_PM.FindControl(pt));
		if (pControl && _tcscmp(pControl->GetClass(), DUI_CTR_BUTTON) != 0 &&
			_tcscmp(pControl->GetClass(), DUI_CTR_OPTION) != 0 &&
			_tcscmp(pControl->GetClass(), _T("CButtonUIEx")) != 0)
			return HTCAPTION;
	}
	return HTCLIENT;
}

LRESULT CMainWnd::OnSysCommand(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	if (wParam == SC_CLOSE)
	{
		Close(0);

		bHandled = TRUE;
		return 0;
	}
	else if (wParam == SC_KEYMENU)
		return 0;

	return CWindowWnd::HandleMessage(uMsg, wParam, lParam);
}
```

```
<?xml version="1.0"?>
<Window size="800,519" mininfo="600,400" caption="0,0,0,32" sizebox="4,4,4,4">
	<Font id="0" name="微软雅黑" size="15" />
	<VerticalLayout bkcolor="#FFF5F5F5" bkcolor2="#FFDCDCDC" bkimage="SysBtn\tanwanlanyue.jpg" normalimage="SysBtn\test.png">
		<!-- 标题栏区 -->
		<HorizontalLayout height="32" bkcolor="#FFDCDCDC" bkcolor2="0xFFFFFFFF">
			<HorizontalLayout height="31" pos="0,0,0,31">
				<Label font="0" name="tital" text="登录界面" width="220" height="32" showhtml="true" autocalcwidth="true" pos="26,0,246,32" float="true" />
			</HorizontalLayout>
			<HorizontalLayout width="95">
				<Button name="minbtn" float="true" pos="0,2,28,30" normalimage=" file='SysBtn\MinNormal.bmp' " />
				<Button name="maxbtn" float="true" pos="30,2,58,30" normalimage=" file='SysBtn\MaxNormal.bmp' " />
				<Button name="restorebtn" visible="false" tooltip="还原" float="true" pos="30,2,58,30" normalimage=" file='SysBtn\StoreNormal.bmp' " />
				<Button name="closebtn" float="true" pos="60,2,88,30" normalimage=" file='SysBtn\closeNormal.bmp' " />
			</HorizontalLayout>
		</HorizontalLayout>
		<VerticalLayout height="493" pos="0,0,0,493">
			<Edit name="account" width="224" height="25" pos="106,228,330,253" float="true" />
			<Label text="账号：" width="41" height="25" font="0" textcolor="0xFF000000" pos="66,228,107,253" float="true" bkcolor="0xFFFFFFFF" />
			<Edit name="password" width="225" height="25" password="true" pos="103,274,328,299" float="true" />
			<Label text="密码：" width="37" height="25" font="0" textcolor="0xFF000000" pos="66,274,103,299" float="true" bkcolor="0xFFFFFFFF" />
			<Button name="sign" width="110" height="39" text="登录" font="0" pos="335,359,445,398" float="true" bkcolor="0xFFFF0000" />
			<Button name="idea" width="121" height="127" pos="554,3,675,130" float="true" />
		</VerticalLayout>
	</VerticalLayout>
</Window>
```

![image.png](https://s0rry-1308583710.cos.ap-chengdu.myqcloud.com/markdown/20240226025747.png)

## 总结

至此，就已经可以在windows上写桌面级的的程序啦。duilib的轻量级是我使用它的原因，这个框架结合xml来绘制窗口，是一个当前比较完善的图形化方案。安卓也是用的类似的图形化思想，学完这个再去学安卓的app编写，给我一中似曾相识的感觉。

当然duilib的后面还有更加高级的用法，但是对于我来说用处不大，这里没有写出来了。
