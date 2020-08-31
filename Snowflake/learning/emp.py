import learning.test as directory
import learning.generator as id_generator

emp_id = id_generator._id()

if __name__ == '__main__':
    directory.add_employee(emp_id=next(emp_id), emp_name='Srinivas', emp_ph_number=9769761420)
    directory.add_employee(emp_id=next(emp_id), emp_name='Rama', emp_ph_number=9999999999)
    print(directory.filter_by(lambda e: e == 1))



