import PySimpleGUI as sg
import time
import threading
inner='1'
text=sg.Text(inner)
list_view = sg.Listbox(['item 1', 'item 2'])

rows = [[1, 'Rajeev', 23, 78],
        [2, 'Rajani', 21, 66],
        [3, 'Rahul', 22, 60],
        [4, 'Robin', 20, 75]]
def getNetlink():
    #获取来自内核netlink的数据

    #更新listbox
    return 0




def long_time_work(window):
    global inner,text
    for i in range(10):
        time.sleep(1)
        window.write_event_value('任务进度', i)
        inner+='1'
        text.update(inner)

    window.write_event_value('任务结束', '')


def detail_window(x,y):
    #数据包详细信息框弹窗
    layout=[[sg.Text(rows[x][y])]]
    window=sg.Window("detail",layout)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
    window.close()

def main_window():
    #创建主窗口
    sg.set_options(font=("Arial Bold", 14))
    #开始和停止按钮
    upButtons=[sg.B('start'),sg.B('stop')]
    #过滤信息

    #myshark数据包显示窗口
    toprow = ['S.No.', 'Name', 'Age', 'Marks']
    #使用listbox显示更加平滑
    tbl1 = sg.Listbox(values=rows,
                     key='-TABLE-',

                     enable_events=True,
                     expand_x=True,
                     expand_y=True,
                     )
    #详细信息显示
    layout = [[upButtons],[tbl1],[sg.B('mad')]]
    window = sg.Window("Table Demo", layout,size=(500,300), resizable=True)
    return window
#window = sg.Window('耗时任务演示', layout)
def build_data(window):
    #模拟数据产生
    i=5
    while True:
        time.sleep(0.5)
        row=[i,'mky',i*2,i*3]
        i+=1
        rows.append(row)
        window['-TABLE-'].update(values=rows,scroll_to_index=i)
        window.refresh()



def main():

    window=main_window()
    thread=threading.Thread(target=build_data, args=(window,) ,daemon=True)
    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED:
            break
        if event == 'start':
            thread.start()

        #获取listbox点击信息
        for row in values['-TABLE-'] :
            print(row)


    window.close()

if __name__ == '__main__':

    main()

