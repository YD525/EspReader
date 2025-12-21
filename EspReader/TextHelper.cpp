#include "TextHelper.h"

bool HasVisibleText(const std::string& Utf8)
{
	if (Utf8.empty())
		return false;

	const unsigned char* Array =
		reinterpret_cast<const unsigned char*>(Utf8.data());

	size_t i = 0;
	while (i < Utf8.size())
	{
		unsigned char Char = Array[i];

		if (Char < 0x80)
		{
			if (!std::isspace(Char))
				return true;
			i++;
		}
		else
		{
			if (i + 2 < Utf8.size() && Array[i] == 0xE3 && Array[i + 1] == 0x80 && Array[i + 2] == 0x80)
			{
				i += 3;
			}
			else
			{
				return true;
			}
		}	
	}
	return false;
}