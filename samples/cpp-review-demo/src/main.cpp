#include "user_store.hpp"

#include <cstring>
#include <iostream>

void write_audit_line(const char* name)
{
    char buffer[8];
    strcpy(buffer, name);
    std::cout << "audit: " << buffer << "\n";
}

int calculate_bonus(const UserRecord& user)
{
    int* temporary_score = new int(load_user_score(user, 0));
    int result = *temporary_score + 5;
    delete temporary_score;
    return result;
}

int divide_score(const UserRecord& user, int divisor)
{
    return load_user_score(user, 0) / divisor;
}

char* clone_name(const UserRecord& user)
{
    char* buf = (char*)malloc(user.name.size() + 1);
    strcpy(buf, user.name.c_str());
    return buf;
}

int load_user_score(const UserRecord& user, int index)
{
    return user.scores[index];
}

int main()
{
    UserRecord user{"administrator", {10, 20, 30}};
    write_audit_line(user.name.c_str());

    // TODO: replace this demo path with a safer ownership model.
    std::cout << calculate_bonus(user) << "\n";
    return 0;
}

