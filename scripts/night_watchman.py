import time
import datetime
import subprocess
import signal
import sys
import os

# 配置时间段（使用 24 小时制）
START_HOUR = 23
END_HOUR = 8

def is_active_window():
    now = datetime.datetime.now().time()
    start_time = datetime.time(START_HOUR, 0)
    end_time = datetime.time(END_HOUR, 0)
    
    # 比如 23:00 到 08:00
    if start_time > end_time:
        return now >= start_time or now < end_time
    else:
        return start_time <= now < end_time

def get_seconds_until_next_start():
    now = datetime.datetime.now()
    target = now.replace(hour=START_HOUR, minute=0, second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=1)
    return (target - now).total_seconds()

if __name__ == "__main__":
    process = None
    
    def signal_handler(sig, frame):
        print("\n[Watchman] 收到退出信号，正在优雅关闭 Z-Scope...")
        if process and process.poll() is None:
            try:
                # 给子进程组发信号，以防连带主进程被杀
                os.kill(process.pid, signal.CTRL_C_EVENT)
                process.wait(timeout=10)
            except Exception:
                process.kill()
        sys.exit(0)
        
    # 绑定被手动 Ctrl+C 时的清理逻辑
    signal.signal(signal.SIGINT, signal_handler)
    
    print("=" * 60)
    print("🌙 Z-Scope 免费时段守夜人脚本启动！")
    print(f"设定扫描时段：每天 {START_HOUR:02d}:00 至 {END_HOUR:02d}:00")
    print("=" * 60)

    while True:
        if is_active_window():
            print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🕒 到达优惠时段，启动 Z-Scope 扫描...")
            
            # 使用刚才新增的 --resume-from auto
            cmd = ["zscope", "-c", "zscope.yaml", "--resume-from", "auto"]
            
            # 使用 CREATE_NEW_PROCESS_GROUP 以便随后能独立发送 Ctrl+C
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
            
            process = subprocess.Popen(cmd, creationflags=creationflags)
            
            # 持续监控
            while is_active_window():
                if process.poll() is not None:
                    # 进程退出了
                    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ⚠️ Z-Scope 进程已退出，状态码：{process.poll()}")
                    if process.poll() == 0:
                        print("\n🎉🎉🎉 太棒了！所有接口都已经全面扫描完毕！")
                        sys.exit(0)
                    else:
                        print("出现意外错误或崩溃，将在 60 秒后重新尝试拉起续扫...")
                        time.sleep(60)
                        break  # 跳出监控循环重新进入大循环
                time.sleep(10)
            
            # 时间到了 08:00，但依然活跃，说明免费期结束
            if process and process.poll() is None:
                print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ☀️ 免费时段结束，发送暂停指令，保存进度...")
                try:
                    if sys.platform == 'win32':
                        # 发送 CTRL_BREAK_EVENT 给子进程组，会被 Z-Scope 捕获并执行存库中断逻辑
                        os.kill(process.pid, signal.CTRL_BREAK_EVENT)
                    else:
                        process.send_signal(signal.SIGINT)
                    # 等待最多 30 秒让 Z-Scope 写入 SQLite 并退出
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    print("Z-Scope 响应超时被强制关闭，请检查数据。")
                    process.kill()
                except Exception as e:
                    print(f"关闭子进程时发生错误: {e}")
                finally:
                    process = None
                
        else:
            # 不在活跃时间，计算距离晚上 23:00 还有多远
            wait_seconds = get_seconds_until_next_start()
            hours = wait_seconds / 3600
            print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 💤 当前是非优惠时段，进入休眠，等待 {hours:.1f} 小时直至 {START_HOUR:02d}:00...")
            
            # 为了防止被系统挂起，每次只睡 1 分钟
            end_sleep_time = time.time() + wait_seconds
            while time.time() < end_sleep_time:
                # 检查是否刚好处在时间窗口（应对电脑休眠刚醒的情况）
                if is_active_window():
                    break
                time.sleep(60)
