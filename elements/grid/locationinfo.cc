/*
 * locationinfo.{cc,hh} -- element gives the grid node's current location
 * Douglas S. J. De Couto
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology.
 *
 * This software is being provided by the copyright holders under the GNU
 * General Public License, either version 2 or, at your discretion, any later
 * version. For more information, see the `COPYRIGHT' file in the source
 * distribution.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include "locationinfo.hh"
#include "glue.hh"
#include "confparse.hh"
#include "router.hh"
#include "error.hh"

LocationInfo::LocationInfo()
{
  _move = 0;
  _lat0 = 32.2816;  // Doug's house in Bermuda.
  _lon0 = -64.7685;
  _t0 = 0;
  _t1 = 0;
  _vlat = 0;
  _vlon = 0;
}

LocationInfo::~LocationInfo()
{
}

int
LocationInfo::read_args(const Vector<String> &conf, ErrorHandler *errh)
{
  bool do_move = false;
  int lat_int, lon_int;
  int res = cp_va_parse(conf, this, errh,
			// 5 fractional digits ~= 1 metre precision
			cpReal, "latitude (decimal degrees)", 5, &lat_int,
			cpReal, "longitude (decimal degrees)", 5, &lon_int,
                        cpOptional,
                        cpBool, "move?", &do_move,
			0);
  float lat = ((float) lat_int) / 100000.0f;
  float lon = ((float) lon_int) / 100000.0f; 
  if (lat > 90 || lat < -90)
    return errh->error("%s: latitude must be between +/- 90 degrees", id().cc());
  if (lon > 180 || lon < -180)
    return errh->error("%s: longitude must be between +/- 180 degrees", id().cc());

  _lat0 = lat;
  _lon0 = lon;
  _move = do_move;

  return res;
}
int
LocationInfo::configure(const Vector<String> &conf, ErrorHandler *errh)
{
  return read_args(conf, errh);
}

double
LocationInfo::now()
{
  struct timeval tv;
  double t;

  click_gettimeofday(&tv);
  t = tv.tv_sec + (tv.tv_usec / 1000000.0);
  return(t);
}

double
LocationInfo::xlat()
{
  if(_move){
    return(_lat0 + _vlat * (now() - _t0));
  } else {
    return(_lat0);
  }
}

double
LocationInfo::xlon()
{
  if(_move){
    return(_lon0 + _vlon * (now() - _t0));
  } else {
    return(_lon0);
  }
}

double
LocationInfo::uniform()
{
  double x;
        
  x = (double)random() / 0x7fffffff;
  return(x);
}

// Pick a new place to move to, and a time by which we want
// to arrive there.
// Intended to be overridden.
void
LocationInfo::choose_new_leg(double *nlat, double *nlon, double *nt)
{
  *nlat = _lat0 + 0.0001 - (uniform() * 0.0002);
  *nlon = _lon0 + 0.0001 - (uniform() * 0.0002);
  *nt = _t0 + 20 * uniform();
}

grid_location
LocationInfo::get_current_location()
{
  double t = now();

  if(_move == 1 && t >= _t1){
    _lat0 = xlat();
    _lon0 = xlon();
    _t0 = t;
    double nlat = 0, nlon = 0, nt = 0;
    choose_new_leg(&nlat, &nlon, &nt);
    assert(nt > 0);
    _vlat = (nlat - _lat0) / (nt - _t0);
    _vlon = (nlon - _lon0) / (nt - _t0);
    _t1 = nt;
  }

  if (_move == 2) {
    _lat0 = xlat();
    _lon0 = xlon();
    _t0 = t;
  }

  grid_location gl(xlat(), xlon());
  return(gl);
}

static String
loc_read_handler(Element *f, void *)
{
  LocationInfo *l = (LocationInfo *) f;
  grid_location loc = l->get_current_location();
  
  const int BUFSZ = 255;
  char buf[BUFSZ];
  int res = snprintf(buf, BUFSZ, "%f, %f\n", loc.lat(), loc.lon());
  if (res < 0) {
    click_chatter("LocationInfo read handler buffer too small");
    return String("");
  }
  return String(buf);  
}


static int
loc_write_handler(const String &arg, Element *element,
		  void *, ErrorHandler *errh)
{
  LocationInfo *l = (LocationInfo *) element;
  Vector<String> arg_list;
  cp_argvec(arg, arg_list);
  
  return l->read_args(arg_list, errh);
}

void
LocationInfo::add_handlers()
{
  add_default_handlers(true);
  add_write_handler("loc", loc_write_handler, (void *) 0);
  add_read_handler("loc", loc_read_handler, (void *) 0);
}


void
LocationInfo::set_new_dest(double v_lat, double v_lon)
{ /* velocities v_lat and v_lon in degrees per sec */

  double t = now();
  
  _lat0 = xlat();
  _lon0 = xlon();
  _t0 = t;
  _vlat = v_lat;
  _vlon = v_lon;
}


ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(LocationInfo)
