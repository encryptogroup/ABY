import xlrd
import csv
import sys, getopt


def csv_from_excel(filename):
    wb = xlrd.open_workbook(filename)
    sh = wb.sheet_by_index(0)
    your_csv_file = open('data.csv', 'w')
    wr = csv.writer(your_csv_file, quoting=csv.QUOTE_ALL)

    for rownum in range(sh.nrows):
        wr.writerow(sh.row_values(rownum))

    your_csv_file.close()

# runs the csv_from_excel function:


def main(argv):
    
        filename = 'dataS1.xlsx'
        try:
                opts, args = getopt.getopt(argv,"hf:",["file="])
        except getopt.GetoptError:
            print 'csvConvert.py -f <file>'
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print 'csvConvert.py -f <file>'
                sys.exit()
            elif opt in ("-f", "--file"):
                loc = str(arg)
            else: 
                print('ERROR.py -f <file>')
        
        csv_from_excel(filename)
                    

if __name__ == "__main__":
    main(sys.argv[1:])