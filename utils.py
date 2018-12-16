def in_cache(cache_store:dict, cached_arg_num=0, cached_arg_name=None):

    def get_decorator(cached_func):

        def calling_func(*args, **kwargs):
            if cached_arg_name is not None and cached_arg_name in kwargs:
                cached_var = kwargs[cached_arg_name]
            else:
                cached_var = args[cached_arg_num]

            if cached_var is not None and cached_var in cache_store:
                return cache_store[cached_var]

            func_data = cached_func(*args, **kwargs)

            if func_data is not None and cached_var is not None:
                cache_store[cached_var] = func_data

            return func_data

        return calling_func

    return get_decorator
