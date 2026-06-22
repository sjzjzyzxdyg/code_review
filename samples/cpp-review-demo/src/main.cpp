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
    return result;
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

