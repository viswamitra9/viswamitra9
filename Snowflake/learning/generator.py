def _id():
    """
    Generate the unique number and return the number
    :return:
    """
    i = 0
    while True:
        yield i
        i = i + 1
