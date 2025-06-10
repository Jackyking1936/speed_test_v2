import logging

def get_logger(name: str='default_logger', log_file: str='app.log', log_level=logging.DEBUG) -> logging.Logger:
    logger = logging.getLogger(name)
    
    if logger.hasHandlers():
        return logger  # 避免重複添加 handler

    logger.setLevel(log_level)

    formatter = logging.Formatter(
        fmt="[%(asctime)s.%(msecs)03d][%(name)s][%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger