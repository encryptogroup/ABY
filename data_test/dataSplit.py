#!/usr/bin/python


##This script takes one xlsx with two columns (longitude and latitude / X and Y coordinates) and creates two other files
##containing each the shares of these coordinates


import xlrd
import xlsxwriter
from random import randrange
import sys, getopt


## X will be splitted in x1 and x2 where x1+x2=X
def create_shares_of_value(valueToShare):
    random = randrange(8)
    
    result = []
    oneShare = valueToShare - random
    twoShare = random
    result.append(oneShare)
    result.append(twoShare)
    

    
    return result
          
          
          
def main(argv):
    
        loc = 'test.xlsx'
        try:
                opts, args = getopt.getopt(argv,"hf:",["file="])
        except getopt.GetoptError:
            print 'dataSplit.py -f <file>'
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print 'dataSplit.py -f <file>'
                sys.exit()
            elif opt in ("-f", "--file"):
                loc = str(arg)
            else:
                print('ERROR.py -f <file>')
                    

        wb = xlrd.open_workbook(loc)
        nsheets = len(wb.sheet_names())

        ##Creating a list
        ##each pair x11 x12 y11 y12 are just one set of coordinates
        x1_s1 =[]#  [0]*(nrows-2)
        x1_s2 =[]#  [0]*(nrows-2)

        x2_s1 =[]#  [0]*(nrows-2)
        x2_s2 =[]#  [0]*(nrows-2)
        
        y1_s1 =[]#  [0]*(nrows-2)
        y1_s2 =[]#  [0]*(nrows-2)
        
        y2_s1 =[]#  [0]*(nrows-2)
        y2_s2 =[]#  [0]*(nrows-2)
        
        
        ##evaluate all the sheets of the file
        for j in range(0,1):

            ##number of sheets
            sheet = wb.sheet_by_index(j)
            ##Extracting number of rows
            nrows = sheet.nrows

            x_start = [] #[0]*(nrows-2)
            y_start = [] #[0]*(nrows-2)
            x_end = [] #[0]*(nrows-2)
            y_end = [] #[0]*(nrows-2)
            
            ## Take all the rows but no the heading
            for i in range(1,nrows):
    
                ##Creating shares of coordinate X of the point in row i
                x_start.append(float(sheet.cell_value(i,0)))
                shares = create_shares_of_value(x_start[i-1])
                x1_s1.append(shares[0])
                x1_s2.append(shares[1])

    
                ##Creating shares of coordinate Y of the point in row i
                y_start.append(float(sheet.cell_value(i, 1)))
                shares = create_shares_of_value(y_start[i-1])
                y1_s1.append(shares[0])
                y1_s2.append(shares[1])
                
                
                ##Creating shares of coordinate X_End of the point in row i
                x_end.append(float(sheet.cell_value(i,2)))
                shares = create_shares_of_value(x_end[i-1])
                x2_s1.append(shares[0])
                x2_s2.append(shares[1])
                
                ##Creating shares of coordinate Y of the point in row i
                y_end.append(float(sheet.cell_value(i, 3)))
                shares = create_shares_of_value(y_end[i-1])
                y2_s1.append(shares[0])
                y2_s2.append(shares[1])
        
            wbS1 = xlsxwriter.Workbook('./dataS1.xlsx')
            wbS2 = xlsxwriter.Workbook('./dataS2.xlsx')

            sheetS1 = wbS1.add_worksheet('points')
            sheetS2 = wbS2.add_worksheet('points')

            sheetS1.write(0,0,'Share Start X')
            sheetS1.write(0,1,'Share Start Y')
            sheetS1.write(0,2,'Share End X')
            sheetS1.write(0,3,'Share End Y')
            sheetS2.write(0,0,'Share Start X')
            sheetS2.write(0,1,'Share Start Y')
            sheetS2.write(0,2,'Share End X')
            sheetS2.write(0,3,'Share End Y')

            sheetS1.write_column(1,0,x1_s1)
            sheetS1.write_column(1,1,y1_s1)
            sheetS1.write_column(1,2,x2_s1)
            sheetS1.write_column(1,3,y2_s1)
            sheetS2.write_column(1,0,x1_s2)
            sheetS2.write_column(1,1,y1_s2)
            sheetS2.write_column(1,2,x2_s2)
            sheetS2.write_column(1,3,y2_s2)
            wbS1.close()
            wbS2.close()


if __name__ == "__main__":
    main(sys.argv[1:])
