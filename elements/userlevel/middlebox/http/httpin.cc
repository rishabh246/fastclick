#include <click/config.h>
#include "httpin.hh"
#include <click/router.hh>
#include <click/args.hh>
#include <click/error.hh>

CLICK_DECLS

HTTPIn::HTTPIn()
{
    headerFound = false;
}

int HTTPIn::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return 0;
}

Packet* HTTPIn::processPacket(Packet* p)
{
    WritablePacket *packet = p->uniqueify();

    if(!headerFound)
    {
        //removeHeader(packet, "Content-Length");
        //removeHeader(packet, "Transfer-Encoding");
    }

    // Compute the offset of the HTML payload
    const char* source = strstr((const char*)getPacketContentConst(packet), "\r\n\r\n");
    if(source != NULL)
    {
        uint32_t offset = (int)(source - (char*)packet->data() + 4);
        setContentOffset(packet, offset);
        headerFound = true;
    }

    return packet;
}

void HTTPIn::removeHeader(WritablePacket* packet, const char* header)
{
    unsigned char* source = getPacketContent(packet);
    unsigned char* beginning = (unsigned char*)strstr((char*)source, header);
    if(beginning == NULL)
        return;
    else
        click_chatter("Found!");
    unsigned char* end = (unsigned char*)strstr((char*)beginning, "\r\n");
    if(end == NULL)
        return;
    click_chatter("End: %d",(end - beginning));
    unsigned nbBytesToRemove = (end - beginning) + strlen("\r\n");

    click_chatter("Bytes to remove: %u", nbBytesToRemove);


    uint32_t position = beginning - packet->data();

    removeBytes(packet, position, nbBytesToRemove);
    modifyPacket(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HTTPIn)
//ELEMENT_MT_SAFE(HTTPIn)
