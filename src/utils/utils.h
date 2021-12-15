#ifndef UTILS_H
#define UTILS_H

#include "common.h"


void print_chunk_arr(std::vector<std::vector<unsigned char> > _chunkArr);
int get_number_of_files(std::string _dirPath);
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
std::string get_md5(std::string _data);
bool parse_config();
double calc_mean(std::vector<double> v);
double calc_std(std::vector<double> v);

// trim from left 
inline std::string& ltrim(std::string& s, const char* t = " \t\n\r\f\v\0")
{
	s.erase(0, s.find_first_not_of(t));
	return s;
}
// trim from right 
inline std::string& rtrim(std::string& s, const char* t = " \t\n\r\f\v\0")
{
	s.erase(s.find_last_not_of(t) + 1);
	return s;
}
// trim from left & right 
inline std::string& trim(std::string& s, const char* t = " \t\n\r\f\v\0")
{
	return ltrim(rtrim(s, t), t);
}

#include "utils.hpp"
#endif