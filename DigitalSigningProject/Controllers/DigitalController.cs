namespace DigitalSigningProject.Controllers
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class DigitalController : Controller
    {
        // GET: DigitalController
        public ActionResult Index()
        {
            return View();
        }

        // GET: DigitalController/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: DigitalController/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: DigitalController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: DigitalController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: DigitalController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: DigitalController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: DigitalController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}
