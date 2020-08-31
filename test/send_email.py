def test():
     html = """
     <html>
     <head>
     <style> 
       table, th, td {{ border: 1px solid black; border-collapse: collapse; }}
       th, td {{ padding: 5px; }}
     </style>
     </head>
     <body><p>Hello, Friend.</p>
     <p>Here is your data:</p>
     {table}
     <p>Regards,</p>
     <p>Me</p>
     </body></html>
     """