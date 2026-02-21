# 1. 使用 Python 官方轻量级镜像
FROM python:3.10-slim

# 2. 设置环境变量与时区 (确保定时任务不乱)
ENV TZ=Asia/Shanghai
ENV PYTHONUNBUFFERED=1

# 安装系统基础依赖（时区配置需要）
RUN apt-get update && apt-get install -y tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# 3. 设置工作目录
WORKDIR /app

# 4. 复制依赖清单并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 复制代码到容器内
COPY . .

# 6. 声明 Web 运行端口
EXPOSE 5000

# 7. 终极启动命令：使用 Gunicorn 启动 Flask，启用单进程多线程模式（完美兼容定时任务）
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5000", "app:app"]
