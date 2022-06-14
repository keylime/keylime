def retry_time(exponential, base, ntries, logger):
    if exponential:
        if base > 1:
            return base**ntries
        if logger:
            logger.warning("Base %f incompatible with exponential backoff", base)

    return abs(base)
