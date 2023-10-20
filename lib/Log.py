class Log:
    
    @staticmethod 
    def info(*args: list):
        print(f'INFO: {args}', flush=True)

    @staticmethod
    def error(*args: list):
        print(f'ERROR: {args}', flush=True)
