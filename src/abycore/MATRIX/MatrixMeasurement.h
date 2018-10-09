//
// Created by liork on 8/22/18.
//

#ifndef ABY_MATRIXMEASUREMENT_H
#define ABY_MATRIXMEASUREMENT_H

#include <string>
#include <chrono>
#include <fstream>
#include <iostream>
#include <unistd.h>


using namespace std;
using namespace std::chrono;

class MatrixMeasurement
{
private:
    string getcwdStr() const
    {
        char buff[256];
        auto res = getcwd(buff, 255);
        assert(res != NULL);
        return std::string(buff);
    }

    size_t getTaskIdx(string name) const
    {
        auto it = std::find(m_tasksNames.begin(), m_tasksNames.end(), name);
        auto idx = distance(m_tasksNames.begin(), it);
        return idx;
    }

    size_t numberOfIterations;
    vector<string> m_tasksNames;
    vector<vector<long>> m_cpuStartTimes;
    vector<vector<long>> m_cpuEndTimes;
    string m_arguments = "";

public:
    MatrixMeasurement(size_t argc, char* argv[], vector<string> tasksNames, size_t numberOfIterations):
            numberOfIterations(numberOfIterations),
            m_tasksNames(tasksNames),
            m_cpuStartTimes(vector<vector<long>>(tasksNames.size(), vector<long>(numberOfIterations))),
            m_cpuEndTimes(vector<vector<long>>(tasksNames.size(), vector<long>(numberOfIterations)))
    {

        for(size_t idx = 0; idx < argc; ++idx)
        {
            string s(argv[idx]);
            if (idx < argc - 1)
                m_arguments += s + "*";
            else
                m_arguments += s;
        }

    }

    auto get_ms_since_epoch() const
    {
        //Cast the time point to ms, then get its duration, then get the duration's count.
        auto now = system_clock::now();
        return time_point_cast<milliseconds>(now).time_since_epoch().count();
    }

    void startSubTask(string taskName, size_t currentIterationNumber)
    {
        auto taskIdx = getTaskIdx(taskName);
        m_cpuStartTimes[taskIdx][currentIterationNumber] = get_ms_since_epoch();
    }

    void endSubTask(string taskName, size_t currentIterationNumber)
    {
        auto taskIdx = getTaskIdx(taskName);
        m_cpuEndTimes[taskIdx][currentIterationNumber] = get_ms_since_epoch();

        // if this is the last task and last iteration write the data to file
        if (taskIdx == m_tasksNames.size() - 1 && currentIterationNumber == m_cpuEndTimes[0].size() - 1)
        {
            write_log();
        }
    }

    void write_log() const
    {
        string logFileName = getcwdStr() + "/../../MATRIX/logs/" + m_arguments + ".log";
        ofstream logFile(logFileName);
        if (!logFile.is_open())
        {
            cerr << "MatrixMeasurement: Could not open log file '"
                 << logFileName
                 << "'\n";
            return;
        }
        //write to file
        for (size_t task_idx = 0; task_idx < m_tasksNames.size(); ++task_idx)
        {
            logFile << m_tasksNames[task_idx] + ":";
            cout << "taskName : " << m_tasksNames[task_idx] << endl;
            for (size_t iteration = 0; iteration < numberOfIterations; ++iteration)
            {
                cout << "value : " << m_cpuEndTimes[task_idx][iteration] << endl;
                logFile << to_string(m_cpuEndTimes[task_idx][iteration]
                                     - m_cpuStartTimes[task_idx][iteration])
                        << ",";
            }

            logFile << "\n";
        }
        logFile.close();
    }
};

#endif //ABY_MATRIXMEASUREMENT_H
